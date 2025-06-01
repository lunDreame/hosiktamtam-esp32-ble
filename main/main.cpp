#include <string>
#include <map>
#include <vector>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <esp_log.h>
#include <esp_timer.h>
#include <nvs_flash.h>
#include <nvs.h>
#include <esp_bt.h>
#include <esp_bt_main.h>
#include <esp_wifi.h>
#include <esp_event.h>
#include <esp_netif.h>
#include <esp_http_client.h>
#include <esp_gap_ble_api.h>
#include <esp_http_server.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <mbedtls/sha256.h>

#define DEFAULT_SSID "YOUR_WIFI_SSID"
#define DEFAULT_PASS "YOUR_WIFI_PASS"
#define RSSI_THRESHOLD -80
#define API_ENDPOINT "https://your.server.com/api/ble_rssi"

static const char *TAG = "BLE_MONITOR";

struct RssiStats {
    int total_rssi = 0;
    int count = 0;
};

std::map<std::string, RssiStats> rssi_stats;

std::string anonymize_mac(const std::string &mac) {
    uint8_t hash[32];
    mbedtls_sha256((const unsigned char *)mac.c_str(), mac.length(), hash, 0);
    std::ostringstream oss;
    for (int i = 0; i < 8; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return oss.str();
}

std::string get_iso_timestamp() {
    time_t now = time(nullptr);
    struct tm t;
    gmtime_r(&now, &t);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &t);
    return std::string(buf);
}

void save_wifi_config(const char *ssid, const char *pass) {
    nvs_handle_t handle;
    if (nvs_open("wifi_config", NVS_READWRITE, &handle) == ESP_OK) {
        nvs_set_str(handle, "ssid", ssid);
        nvs_set_str(handle, "password", pass);
        nvs_commit(handle);
        nvs_close(handle);
        ESP_LOGI(TAG, "Saved Wi-Fi credentials to NVS");
    }
}

bool load_wifi_config(char *ssid_out, size_t ssid_size, char *pass_out, size_t pass_size) {
    nvs_handle_t handle;
    esp_err_t err = nvs_open("wifi_config", NVS_READONLY, &handle);
    if (err != ESP_OK) return false;

    err = nvs_get_str(handle, "ssid", ssid_out, &ssid_size);
    if (err != ESP_OK) {
        nvs_close(handle);
        return false;
    }

    err = nvs_get_str(handle, "password", pass_out, &pass_size);
    nvs_close(handle);
    return err == ESP_OK;
}

void send_data_to_server() {
    if (rssi_stats.empty()) return;

    std::string timestamp = get_iso_timestamp();
    std::string payload = "{ \"timestamp\": \"" + timestamp + "\", \"devices\": [";
    bool first = true;

    for (const auto &[mac, stats] : rssi_stats) {
        if (stats.count == 0) continue;
        float avg_rssi = (float)stats.total_rssi / stats.count;
        std::string anon_mac = anonymize_mac(mac);

        if (!first) payload += ",";
        payload += "{ \"mac\": \"" + anon_mac + "\", \"rssi\": " + std::to_string((int)avg_rssi) + " }";
        first = false;
    }
    payload += "] }";

    esp_http_client_config_t config = {
        .url = API_ENDPOINT,
        .method = HTTP_METHOD_POST,
    };
    esp_http_client_handle_t client = esp_http_client_init(&config);
    esp_http_client_set_header(client, "Content-Type", "application/json");
    esp_http_client_set_post_field(client, payload.c_str(), payload.length());

    esp_err_t err = esp_http_client_perform(client);
    if (err == ESP_OK)
        ESP_LOGI(TAG, "Data sent. Status: %d", esp_http_client_get_status_code(client));
    else
        ESP_LOGE(TAG, "Failed to send: %s", esp_err_to_name(err));

    esp_http_client_cleanup(client);
    rssi_stats.clear();
}

void gap_cb(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t *param) {
    if (event == ESP_GAP_BLE_SCAN_RESULT_EVT &&
        param->scan_rst.search_evt == ESP_GAP_SEARCH_INQ_RES_EVT) {

        int rssi = param->scan_rst.rssi;
        if (rssi < RSSI_THRESHOLD) return;

        char mac_str[18];
        snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                 param->scan_rst.bda[0], param->scan_rst.bda[1], param->scan_rst.bda[2],
                 param->scan_rst.bda[3], param->scan_rst.bda[4], param->scan_rst.bda[5]);

        std::string mac(mac_str);
        auto &entry = rssi_stats[mac];
        entry.total_rssi += rssi;
        entry.count += 1;
    }
}

esp_err_t root_get_handler(httpd_req_t *req) {
    const char *html = "<!DOCTYPE html><html><head><meta charset=\"UTF-8\"><title>Wi-Fi 설정</title></head><body><h2>ESP32 Wi-Fi 설정</h2><form method=\"POST\" action=\"/save\">SSID: <input type=\"text\" name=\"ssid\" /><br/>Password: <input type=\"password\" name=\"password\" /><br/><input type=\"submit\" value=\"저장\" /></form></body></html>";
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, html, strlen(html));
    return ESP_OK;
}

esp_err_t save_post_handler(httpd_req_t *req) {
    char buf[128];
    int len = httpd_req_recv(req, buf, sizeof(buf) - 1);
    buf[len] = '\0';

    char ssid[33] = "", password[65] = "";
    sscanf(buf, "ssid=%32[^&]&password=%64s", ssid, password);
    save_wifi_config(ssid, password);

    httpd_resp_sendstr(req, "Saved. rebooting...");
    vTaskDelay(pdMS_TO_TICKS(2000));
    esp_restart();
    return ESP_OK;
}

void start_http_server() {
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    httpd_handle_t server = nullptr;
    httpd_start(&server, &config);

    httpd_uri_t root = {.uri = "/", .method = HTTP_GET, .handler = root_get_handler};
    httpd_uri_t save = {.uri = "/save", .method = HTTP_POST, .handler = save_post_handler};

    httpd_register_uri_handler(server, &root);
    httpd_register_uri_handler(server, &save);
}

void start_softap_mode() {
    esp_netif_create_default_wifi_ap();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);

    wifi_config_t ap_config = {};
    strcpy((char *)ap_config.ap.ssid, "Cafeteria_Setup");
    ap_config.ap.ssid_len = strlen("Cafeteria_Setup");
    ap_config.ap.max_connection = 4;
    ap_config.ap.authmode = WIFI_AUTH_OPEN;

    esp_wifi_set_mode(WIFI_MODE_AP);
    esp_wifi_set_config(WIFI_IF_AP, &ap_config);
    esp_wifi_start();
}

void wifi_init_sta(const char *ssid, const char *pass) {
    esp_netif_create_default_wifi_sta();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);

    wifi_config_t wifi_config = {};
    strncpy((char *)wifi_config.sta.ssid, ssid, sizeof(wifi_config.sta.ssid));
    strncpy((char *)wifi_config.sta.password, pass, sizeof(wifi_config.sta.password));

    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_set_config(WIFI_IF_STA, &wifi_config);
    esp_wifi_start();
    esp_wifi_connect();
}

void ble_task(void *) {
    esp_ble_scan_params_t scan_params = {
        .scan_type = BLE_SCAN_TYPE_ACTIVE,
        .own_addr_type = BLE_ADDR_TYPE_PUBLIC,
        .scan_filter_policy = BLE_SCAN_FILTER_ALLOW_ALL,
        .scan_interval = 0x50,
        .scan_window = 0x30,
        .scan_duplicate = BLE_SCAN_DUPLICATE_DISABLE
    };

    esp_ble_gap_register_callback(gap_cb);
    esp_ble_gap_set_scan_params(&scan_params);

    while (true) {
        rssi_stats.clear();
        esp_ble_gap_start_scanning(5);
        vTaskDelay(pdMS_TO_TICKS(6000));
        esp_ble_gap_stop_scanning();

        send_data_to_server();
        vTaskDelay(pdMS_TO_TICKS(60000));
    }
}

extern "C" void app_main(void) {
    nvs_flash_init();
    esp_netif_init();
    esp_event_loop_create_default();

    char ssid[33], pass[65];
    if (load_wifi_config(ssid, sizeof(ssid), pass, sizeof(pass))) {
        wifi_init_sta(ssid, pass);
        esp_bt_controller_mem_release(ESP_BT_MODE_CLASSIC_BT);
        esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
        esp_bt_controller_init(&bt_cfg);
        esp_bt_controller_enable(ESP_BT_MODE_BLE);
        esp_bluedroid_init();
        esp_bluedroid_enable();
        xTaskCreate(ble_task, "ble_task", 4096, nullptr, 5, nullptr);
    } else {
        start_softap_mode();
        start_http_server();
    }
}