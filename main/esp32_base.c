/**
 * @file esp32_base.c
 * @brief ESP32 WiFi CSI Streaming Application with TCP/HTTP Provisioning
 * 
 * This application provides:
 * - WiFi provisioning via TCP server and HTTP web interface
 * - Automatic reconnection using stored NVS credentials
 * - CSI (Channel State Information) streaming over UDP
 * 
 * The flow is:
 * 1. Check NVS for saved WiFi credentials
 * 2. If credentials exist, try to connect automatically
 * 3. If no credentials or connection fails, start AP mode with provisioning servers
 * 4. User connects to AP and provides credentials via TCP or HTTP
 * 5. Once connected to target WiFi, disable AP and start CSI streaming
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "freertos/ringbuf.h"
#include "esp_system.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "esp_http_server.h"
#include "lwip/err.h"
#include "lwip/sys.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <cJSON.h>


/*===========================================================================*/
/*                              DEFINITIONS                                   */
/*===========================================================================*/

/** Maximum number of WiFi access points to store from scan results */
#define MAX_AP_COUNT 20

/** Maximum length for WiFi SSID */
#define MAX_SSID_LEN 32

/** Maximum length for WiFi password */
#define MAX_PASS_LEN 64

/** UDP port for CSI data streaming */
#define UDP_CSI_PORT 3334

/** TCP port for provisioning server */
#define TCP_PROVISION_PORT 8080

/** HTTP port for web interface */
#define HTTP_PORT 80

/** Maximum CSI data length in bytes */
#define MAX_CSI_LEN 128

/** CSI capture rate control (in milliseconds) */
#define CSI_MIN_INTERVAL_MS 20

/** Traffic generator interval (in milliseconds) */
#define TRAFFIC_GEN_INTERVAL_MS 50

/** Default destination IP for CSI streaming (broadcast address) */
#define CSI_DEST_IP_ADDR "255.255.255.255"

/** Packet type definitions */
#define PKT_TYPE_HEARTBEAT    0x01
#define PKT_TYPE_DATA         0x02
#define PKT_TYPE_ACK          0x03
#define PKT_TYPE_CSI          0x04

/** Packet magic number for validation */
#define PKT_MAGIC             0xCAFE

/** AP configuration for provisioning mode */
#define AP_SSID "ESP32_CSI_Setup"
#define AP_PASS "esp32setup"
#define AP_CHANNEL 1
#define AP_MAX_CONN 4

/** NVS namespace and keys for WiFi credentials */
#define NVS_NAMESPACE "wifi_creds"
#define NVS_KEY_SSID "ssid"
#define NVS_KEY_PASS "password"

/** TCP receive buffer size */
#define TCP_RX_BUF_SIZE 512

/** Connection timeout in milliseconds */
#define WIFI_CONNECT_TIMEOUT_MS 15000

/*===========================================================================*/
/*                          STATIC VARIABLES                                  */
/*===========================================================================*/

/** Logging tag for ESP_LOG macros */
static const char *TAG = "WIFI_PROV";

/** Event group for WiFi connection status signaling */
static EventGroupHandle_t wifi_event_group;

/** Event bit indicating successful WiFi connection */
static const int CONNECTED_BIT = BIT0;

/** Event bit indicating WiFi connection failure */
static const int FAIL_BIT = BIT1;

/** Event bit indicating provisioning mode active */
static const int PROV_MODE_BIT = BIT2;

/** Array to store scanned WiFi access point records */
static wifi_ap_record_t ap_records[MAX_AP_COUNT];

/** Number of access points found during last scan */
static uint16_t ap_count = 0;

/** Packet sequence number (incremented for each packet sent) */
static uint32_t packet_seq = 0;

/** Ring buffer handle for CSI data */
static RingbufHandle_t csi_ringbuf = NULL;

/** UDP socket for CSI streaming (initialized in csi_stream_task) */
static int udp_sock = -1;

/** Destination address for CSI UDP packets */
static struct sockaddr_in csi_dest_addr;

/** Last CSI capture timestamp for rate limiting (in microseconds) */
static volatile int64_t last_csi_time = 0;

/** CSI packet counter (for statistics) */
static volatile uint32_t csi_captured_count = 0;
static volatile uint32_t csi_dropped_count = 0;

/** Network interfaces */
static esp_netif_t *sta_netif = NULL;
static esp_netif_t *ap_netif = NULL;

/** HTTP server handle */
static httpd_handle_t http_server = NULL;

/** Provisioning state */
static bool is_provisioning = false;
static bool sta_connected = false;

/** Mutex for WiFi operations */
static SemaphoreHandle_t wifi_mutex = NULL;

/**
 * @brief Packet structure for UDP communication
 */
#pragma pack(push, 1)
typedef struct {
    uint16_t magic;
    uint8_t version;
    uint8_t type;
    uint32_t seq;
    uint64_t timestamp;
    uint16_t payload_len;
    uint8_t payload[];
} packet_t;
#pragma pack(pop)

typedef struct {
    uint64_t timestamp;
    int8_t rssi;
    uint8_t channel;
    uint8_t len;
    int8_t data[MAX_CSI_LEN];
} csi_payload_t;

/*===========================================================================*/
/*                       FORWARD DECLARATIONS                                 */
/*===========================================================================*/

void csi_stream_task(void *pvParameters);
void traffic_generator_task(void *pvParameters);
void tcp_provision_task(void *pvParameters);
static esp_err_t start_http_server(void);
static void stop_http_server(void);
static bool wifi_connect_sta(const char *ssid, const char *password);
static void start_provisioning_mode(void);
static void stop_provisioning_mode(void);

/*===========================================================================*/
/*                          NVS FUNCTIONS                                     */
/*===========================================================================*/

/**
 * @brief Save WiFi credentials to NVS
 * 
 * @param ssid Network SSID
 * @param password Network password
 * @return ESP_OK on success, error code otherwise
 */
static esp_err_t nvs_save_wifi_credentials(const char *ssid, const char *password)
{
    nvs_handle_t nvs_handle;
    esp_err_t err;
    
    err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open NVS: %s", esp_err_to_name(err));
        return err;
    }
    
    err = nvs_set_str(nvs_handle, NVS_KEY_SSID, ssid);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to save SSID: %s", esp_err_to_name(err));
        nvs_close(nvs_handle);
        return err;
    }
    
    err = nvs_set_str(nvs_handle, NVS_KEY_PASS, password);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to save password: %s", esp_err_to_name(err));
        nvs_close(nvs_handle);
        return err;
    }
    
    err = nvs_commit(nvs_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to commit NVS: %s", esp_err_to_name(err));
    } else {
        ESP_LOGI(TAG, "WiFi credentials saved to NVS");
    }
    
    nvs_close(nvs_handle);
    return err;
}

/**
 * @brief Load WiFi credentials from NVS
 * 
 * @param ssid Buffer to store SSID (must be at least MAX_SSID_LEN bytes)
 * @param password Buffer to store password (must be at least MAX_PASS_LEN bytes)
 * @return ESP_OK on success, ESP_ERR_NOT_FOUND if no credentials, error code otherwise
 */
static esp_err_t nvs_load_wifi_credentials(char *ssid, char *password)
{
    nvs_handle_t nvs_handle;
    esp_err_t err;
    size_t ssid_len = MAX_SSID_LEN;
    size_t pass_len = MAX_PASS_LEN;
    
    err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &nvs_handle);
    if (err != ESP_OK) {
        if (err == ESP_ERR_NVS_NOT_FOUND) {
            ESP_LOGI(TAG, "No saved WiFi credentials found");
        } else {
            ESP_LOGE(TAG, "Failed to open NVS: %s", esp_err_to_name(err));
        }
        return err;
    }
    
    err = nvs_get_str(nvs_handle, NVS_KEY_SSID, ssid, &ssid_len);
    if (err != ESP_OK) {
        ESP_LOGI(TAG, "No SSID stored in NVS");
        nvs_close(nvs_handle);
        return ESP_ERR_NOT_FOUND;
    }
    
    err = nvs_get_str(nvs_handle, NVS_KEY_PASS, password, &pass_len);
    if (err != ESP_OK) {
        ESP_LOGI(TAG, "No password stored in NVS");
        nvs_close(nvs_handle);
        return ESP_ERR_NOT_FOUND;
    }
    
    nvs_close(nvs_handle);
    ESP_LOGI(TAG, "Loaded WiFi credentials from NVS (SSID: %s)", ssid);
    return ESP_OK;
}

/**
 * @brief Clear WiFi credentials from NVS
 * 
 * @return ESP_OK on success, error code otherwise
 */
static esp_err_t nvs_clear_wifi_credentials(void)
{
    nvs_handle_t nvs_handle;
    esp_err_t err;
    
    err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs_handle);
    if (err != ESP_OK) {
        return err;
    }
    
    nvs_erase_key(nvs_handle, NVS_KEY_SSID);
    nvs_erase_key(nvs_handle, NVS_KEY_PASS);
    nvs_commit(nvs_handle);
    nvs_close(nvs_handle);
    
    ESP_LOGI(TAG, "WiFi credentials cleared from NVS");
    return ESP_OK;
}

/*===========================================================================*/
/*                          EVENT HANDLERS                                    */
/*===========================================================================*/

/**
 * @brief WiFi and IP event handler
 */
static void wifi_event_handler(void *arg, esp_event_base_t event_base, 
                                int32_t event_id, void *event_data)
{
    if (event_base == WIFI_EVENT) {
        switch (event_id) {
            case WIFI_EVENT_STA_START:
                ESP_LOGI(TAG, "WiFi STA started");
                break;
                
            case WIFI_EVENT_STA_DISCONNECTED:
                ESP_LOGI(TAG, "Disconnected from AP");
                sta_connected = false;
                xEventGroupSetBits(wifi_event_group, FAIL_BIT);
                xEventGroupClearBits(wifi_event_group, CONNECTED_BIT);
                break;
                
            case WIFI_EVENT_AP_START:
                ESP_LOGI(TAG, "AP started - SSID: %s, Password: %s", AP_SSID, AP_PASS);
                break;
                
            case WIFI_EVENT_AP_STOP:
                ESP_LOGI(TAG, "AP stopped");
                break;
                
            case WIFI_EVENT_AP_STACONNECTED: {
                wifi_event_ap_staconnected_t *event = (wifi_event_ap_staconnected_t *)event_data;
                ESP_LOGI(TAG, "Client connected to AP - MAC: %02x:%02x:%02x:%02x:%02x:%02x",
                         event->mac[0], event->mac[1], event->mac[2],
                         event->mac[3], event->mac[4], event->mac[5]);
                break;
            }
            
            case WIFI_EVENT_AP_STADISCONNECTED: {
                wifi_event_ap_stadisconnected_t *event = (wifi_event_ap_stadisconnected_t *)event_data;
                ESP_LOGI(TAG, "Client disconnected from AP - MAC: %02x:%02x:%02x:%02x:%02x:%02x",
                         event->mac[0], event->mac[1], event->mac[2],
                         event->mac[3], event->mac[4], event->mac[5]);
                break;
            }
        }
    } else if (event_base == IP_EVENT) {
        if (event_id == IP_EVENT_STA_GOT_IP) {
            ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
            ESP_LOGI(TAG, "Got IP: " IPSTR, IP2STR(&event->ip_info.ip));
            sta_connected = true;
            xEventGroupSetBits(wifi_event_group, CONNECTED_BIT);
            xEventGroupClearBits(wifi_event_group, FAIL_BIT);
        }
    }
}

/*===========================================================================*/
/*                          CSI FUNCTIONS                                     */
/*===========================================================================*/

/**
 * @brief WiFi CSI callback function
 */
void wifi_csi_cb(void *ctx, wifi_csi_info_t *info)
{
    if (!info || !info->buf || !csi_ringbuf) return;
    
    int64_t now = esp_timer_get_time();
    
#if CSI_MIN_INTERVAL_MS > 0
    int64_t interval_us = CSI_MIN_INTERVAL_MS * 1000;
    if ((now - last_csi_time) < interval_us) {
        csi_dropped_count++;
        return;
    }
#endif
    
    last_csi_time = now;
    csi_captured_count++;
    
    csi_payload_t payload = {0};
    payload.timestamp = now;
    payload.rssi = info->rx_ctrl.rssi;
    payload.channel = info->rx_ctrl.channel;
    payload.len = info->len > MAX_CSI_LEN ? MAX_CSI_LEN : info->len;
    memcpy(payload.data, info->buf, payload.len);
    
    BaseType_t ret = xRingbufferSendFromISR(csi_ringbuf, &payload, sizeof(payload), NULL);
    if (ret == pdFAIL) {
        csi_dropped_count++;
    }
}

/**
 * @brief Start CSI capture and streaming tasks
 */
static void start_csi_streaming(void)
{
    ESP_LOGI(TAG, "Starting CSI streaming...");
    
    /* Configure CSI */
    wifi_csi_config_t csi_config = {
        .lltf_en = true,
        .htltf_en = true,
        .stbc_htltf2_en = true,
        .ltf_merge_en = true,
        .channel_filter_en = false,
        .manu_scale = false,
        .shift = false,
    };
    
    ESP_ERROR_CHECK(esp_wifi_set_csi_config(&csi_config));
    ESP_ERROR_CHECK(esp_wifi_set_csi_rx_cb(wifi_csi_cb, NULL));
    ESP_ERROR_CHECK(esp_wifi_set_csi(true));
    
    /* Start CSI streaming task */
    xTaskCreatePinnedToCore(csi_stream_task, "csi_stream", 4096, NULL, 5, NULL, 1);
    
    /* Start traffic generator */
#if TRAFFIC_GEN_INTERVAL_MS > 0
    xTaskCreatePinnedToCore(traffic_generator_task, "traffic_gen", 2048, NULL, 4, NULL, 0);
#endif
}

/*===========================================================================*/
/*                          WIFI FUNCTIONS                                    */
/*===========================================================================*/

/**
 * @brief Scan for available WiFi networks
 * 
 * @return Number of networks found
 */
static uint16_t wifi_scan(void)
{
    wifi_scan_config_t scan_config = {
        .ssid = NULL,
        .bssid = NULL,
        .channel = 0,
        .show_hidden = true,
        .scan_type = WIFI_SCAN_TYPE_ACTIVE,
        .scan_time.active.min = 100,
        .scan_time.active.max = 300,
    };
    
    ESP_LOGI(TAG, "Starting WiFi scan...");
    
    esp_err_t err = esp_wifi_scan_start(&scan_config, true);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "WiFi scan failed: %s", esp_err_to_name(err));
        return 0;
    }
    
    ap_count = MAX_AP_COUNT;
    ESP_ERROR_CHECK(esp_wifi_scan_get_ap_records(&ap_count, ap_records));
    
    ESP_LOGI(TAG, "Found %d networks", ap_count);
    return ap_count;
}

/**
 * @brief Connect to a WiFi network in STA mode
 * 
 * @param ssid Network SSID
 * @param password Network password
 * @return true if connection successful, false otherwise
 */
static bool wifi_connect_sta(const char *ssid, const char *password)
{
    if (xSemaphoreTake(wifi_mutex, pdMS_TO_TICKS(5000)) != pdTRUE) {
        ESP_LOGE(TAG, "Failed to acquire WiFi mutex");
        return false;
    }
    
    /* Clear any previous connection events */
    xEventGroupClearBits(wifi_event_group, CONNECTED_BIT | FAIL_BIT);
    
    wifi_config_t wifi_config = {0};
    strncpy((char *)wifi_config.sta.ssid, ssid, sizeof(wifi_config.sta.ssid) - 1);
    strncpy((char *)wifi_config.sta.password, password, sizeof(wifi_config.sta.password) - 1);
    
    ESP_LOGI(TAG, "Connecting to '%s'...", ssid);
    
    esp_err_t err = esp_wifi_set_config(WIFI_IF_STA, &wifi_config);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to set WiFi config: %s", esp_err_to_name(err));
        xSemaphoreGive(wifi_mutex);
        return false;
    }
    
    err = esp_wifi_connect();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start WiFi connect: %s", esp_err_to_name(err));
        xSemaphoreGive(wifi_mutex);
        return false;
    }
    
    xSemaphoreGive(wifi_mutex);
    
    /* Wait for connection result */
    EventBits_t bits = xEventGroupWaitBits(wifi_event_group,
                                           CONNECTED_BIT | FAIL_BIT,
                                           pdFALSE, pdFALSE,
                                           pdMS_TO_TICKS(WIFI_CONNECT_TIMEOUT_MS));
    
    if (bits & CONNECTED_BIT) {
        ESP_LOGI(TAG, "Successfully connected to '%s'", ssid);
        return true;
    } else {
        ESP_LOGE(TAG, "Failed to connect to '%s'", ssid);
        esp_wifi_disconnect();
        return false;
    }
}

/**
 * @brief Initialize WiFi subsystem in APSTA mode for provisioning
 */
static void wifi_init_apsta(void)
{
    wifi_event_group = xEventGroupCreate();
    wifi_mutex = xSemaphoreCreateMutex();
    
    /* Initialize NVS */
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_LOGW(TAG, "NVS partition issue, erasing and reinitializing...");
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);
    
    /* Initialize TCP/IP stack */
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    
    /* Create network interfaces */
    sta_netif = esp_netif_create_default_wifi_sta();
    ap_netif = esp_netif_create_default_wifi_ap();
    
    /* Initialize WiFi */
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    
    /* Register event handlers */
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL, NULL));
    
    /* Set WiFi mode to APSTA (both AP and STA) */
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    
    /* Configure AP */
    wifi_config_t ap_config = {
        .ap = {
            .ssid = AP_SSID,
            .ssid_len = strlen(AP_SSID),
            .channel = AP_CHANNEL,
            .password = AP_PASS,
            .max_connection = AP_MAX_CONN,
            .authmode = WIFI_AUTH_WPA2_PSK,
            .pmf_cfg = {
                .required = false,
            },
        },
    };
    
    /* If password is empty, make it open */
    if (strlen(AP_PASS) == 0) {
        ap_config.ap.authmode = WIFI_AUTH_OPEN;
    }
    
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap_config));
    
    /* Start WiFi */
    ESP_ERROR_CHECK(esp_wifi_start());
    
    ESP_LOGI(TAG, "WiFi initialized in APSTA mode");
    ESP_LOGI(TAG, "AP SSID: %s, Password: %s", AP_SSID, AP_PASS);
    ESP_LOGI(TAG, "AP IP: 192.168.4.1");
}

/**
 * @brief Switch to STA-only mode (disable AP)
 */
static void wifi_switch_to_sta_only(void)
{
    ESP_LOGI(TAG, "Switching to STA-only mode...");
    
    /* Stop HTTP server if running */
    stop_http_server();
    
    /* Switch to STA mode only */
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    
    is_provisioning = false;
    ESP_LOGI(TAG, "Now in STA-only mode");
}

/**
 * @brief Start provisioning mode (enable AP and servers)
 */
static void start_provisioning_mode(void)
{
    ESP_LOGI(TAG, "Starting provisioning mode...");
    is_provisioning = true;
    xEventGroupSetBits(wifi_event_group, PROV_MODE_BIT);
    
    /* Start HTTP server */
    start_http_server();
    
    /* Start TCP provisioning server */
    xTaskCreatePinnedToCore(tcp_provision_task, "tcp_prov", 4096, NULL, 5, NULL, 0);
    
    ESP_LOGI(TAG, "Provisioning mode active");
    ESP_LOGI(TAG, "Connect to WiFi: %s (password: %s)", AP_SSID, AP_PASS);
    ESP_LOGI(TAG, "Then open http://192.168.4.1 in browser");
    ESP_LOGI(TAG, "Or connect via TCP to 192.168.4.1:%d", TCP_PROVISION_PORT);
}

/**
 * @brief Stop provisioning mode
 */
static void stop_provisioning_mode(void)
{
    ESP_LOGI(TAG, "Stopping provisioning mode...");
    is_provisioning = false;
    xEventGroupClearBits(wifi_event_group, PROV_MODE_BIT);
    
    /* Switch to STA only mode */
    wifi_switch_to_sta_only();
}

/*===========================================================================*/
/*                          HTTP SERVER                                       */
/*===========================================================================*/

/** HTML page for WiFi provisioning */
static const char *HTML_PAGE = 
"<!DOCTYPE html>"
"<html>"
"<head>"
"<meta name='viewport' content='width=device-width,initial-scale=1'>"
"<title>ESP32 CSI Setup</title>"
"<style>"
"*{box-sizing:border-box;margin:0;padding:0}"
"body{font-family:'Segoe UI',system-ui,sans-serif;background:linear-gradient(135deg,#1a1a2e 0%%,#16213e 50%%,#0f3460 100%%);min-height:100vh;color:#e8e8e8;padding:20px}"
".container{max-width:420px;margin:0 auto}"
"h1{text-align:center;margin-bottom:8px;font-size:1.8em;background:linear-gradient(90deg,#00d9ff,#00ff88);-webkit-background-clip:text;-webkit-text-fill-color:transparent;text-shadow:0 0 30px rgba(0,217,255,0.3)}"
".subtitle{text-align:center;color:#888;margin-bottom:24px;font-size:0.9em}"
".card{background:rgba(255,255,255,0.05);backdrop-filter:blur(10px);border-radius:16px;padding:24px;margin-bottom:16px;border:1px solid rgba(255,255,255,0.1);box-shadow:0 8px 32px rgba(0,0,0,0.3)}"
".status{padding:12px 16px;border-radius:8px;margin-bottom:16px;font-size:0.9em}"
".status.scanning{background:rgba(0,217,255,0.15);border:1px solid rgba(0,217,255,0.3);color:#00d9ff}"
".status.success{background:rgba(0,255,136,0.15);border:1px solid rgba(0,255,136,0.3);color:#00ff88}"
".status.error{background:rgba(255,71,87,0.15);border:1px solid rgba(255,71,87,0.3);color:#ff4757}"
".network-list{list-style:none;max-height:300px;overflow-y:auto}"
".network-item{padding:14px 16px;margin:8px 0;background:rgba(255,255,255,0.03);border-radius:10px;cursor:pointer;transition:all 0.2s;border:1px solid transparent;display:flex;justify-content:space-between;align-items:center}"
".network-item:hover{background:rgba(0,217,255,0.1);border-color:rgba(0,217,255,0.3);transform:translateX(4px)}"
".network-item.selected{background:rgba(0,217,255,0.2);border-color:#00d9ff}"
".network-name{font-weight:500}"
".network-info{font-size:0.8em;color:#888}"
".signal{width:20px;height:16px;display:flex;align-items:flex-end;gap:2px}"
".signal span{width:4px;background:#00d9ff;border-radius:1px}"
".signal.weak span:nth-child(1){height:4px}.signal.weak span:nth-child(2){height:8px;opacity:0.3}.signal.weak span:nth-child(3){height:12px;opacity:0.3}"
".signal.medium span:nth-child(1){height:4px}.signal.medium span:nth-child(2){height:8px}.signal.medium span:nth-child(3){height:12px;opacity:0.3}"
".signal.strong span:nth-child(1){height:4px}.signal.strong span:nth-child(2){height:8px}.signal.strong span:nth-child(3){height:12px}"
"input[type=password]{width:100%%;padding:14px 16px;border:1px solid rgba(255,255,255,0.1);border-radius:10px;background:rgba(0,0,0,0.3);color:#fff;font-size:1em;margin:12px 0;transition:border-color 0.2s}"
"input[type=password]:focus{outline:none;border-color:#00d9ff;box-shadow:0 0 0 3px rgba(0,217,255,0.1)}"
"button{width:100%%;padding:14px;border:none;border-radius:10px;font-size:1em;font-weight:600;cursor:pointer;transition:all 0.2s}"
".btn-primary{background:linear-gradient(135deg,#00d9ff,#00b4d8);color:#1a1a2e}"
".btn-primary:hover{transform:translateY(-2px);box-shadow:0 6px 20px rgba(0,217,255,0.4)}"
".btn-primary:disabled{opacity:0.5;cursor:not-allowed;transform:none}"
".btn-secondary{background:rgba(255,255,255,0.1);color:#e8e8e8;margin-top:8px}"
".btn-secondary:hover{background:rgba(255,255,255,0.15)}"
".hidden{display:none}"
"#selectedNetwork{color:#00d9ff;font-weight:500}"
".loader{display:inline-block;width:16px;height:16px;border:2px solid rgba(255,255,255,0.3);border-top-color:#fff;border-radius:50%%;animation:spin 0.8s linear infinite;margin-right:8px;vertical-align:middle}"
"@keyframes spin{to{transform:rotate(360deg)}}"
"</style>"
"</head>"
"<body>"
"<div class='container'>"
"<h1>ESP32 CSI Setup</h1>"
"<p class='subtitle'>WiFi Provisioning</p>"
"<div class='card'>"
"<div id='statusBox' class='status scanning'><span class='loader'></span>Scanning for networks...</div>"
"<ul id='networkList' class='network-list'></ul>"
"<button onclick='scanNetworks()' class='btn-secondary'>Rescan Networks</button>"
"</div>"
"<div id='connectCard' class='card hidden'>"
"<p>Connect to: <span id='selectedNetwork'></span></p>"
"<input type='password' id='password' placeholder='Enter WiFi password'>"
"<button id='connectBtn' onclick='connectWifi()' class='btn-primary'>Connect</button>"
"</div>"
"</div>"
"<script>"
"let selectedSSID='';"
"function scanNetworks(){"
"document.getElementById('statusBox').className='status scanning';"
"document.getElementById('statusBox').innerHTML=\"<span class='loader'></span>Scanning...\";"
"fetch('/scan').then(r=>r.json()).then(data=>{"
"const list=document.getElementById('networkList');"
"list.innerHTML='';"
"data.forEach(n=>{"
"const li=document.createElement('li');"
"li.className='network-item';"
"const sig=n.rssi>-50?'strong':n.rssi>-70?'medium':'weak';"
"li.innerHTML=`<div><div class='network-name'>${n.ssid}</div><div class='network-info'>${n.auth} • Ch ${n.channel}</div></div><div class='signal ${sig}'><span></span><span></span><span></span></div>`;"
"li.onclick=()=>selectNetwork(n.ssid,li);"
"list.appendChild(li);"
"});"
"document.getElementById('statusBox').className='status';"
"document.getElementById('statusBox').textContent=`Found ${data.length} networks`;"
"}).catch(e=>{"
"document.getElementById('statusBox').className='status error';"
"document.getElementById('statusBox').textContent='Scan failed: '+e;"
"});"
"}"
"function selectNetwork(ssid,el){"
"document.querySelectorAll('.network-item').forEach(i=>i.classList.remove('selected'));"
"el.classList.add('selected');"
"selectedSSID=ssid;"
"document.getElementById('selectedNetwork').textContent=ssid;"
"document.getElementById('connectCard').classList.remove('hidden');"
"document.getElementById('password').focus();"
"}"
"function connectWifi(){"
"const pass=document.getElementById('password').value;"
"const btn=document.getElementById('connectBtn');"
"btn.disabled=true;"
"btn.innerHTML=\"<span class='loader'></span>Connecting...\";"
"document.getElementById('statusBox').className='status scanning';"
"document.getElementById('statusBox').innerHTML=\"<span class='loader'></span>Connecting to \"+selectedSSID+\"...\";"
"fetch('/connect',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ssid:selectedSSID,password:pass})})"
".then(r=>r.json()).then(data=>{"
"if(data.success){"
"document.getElementById('statusBox').className='status success';"
"document.getElementById('statusBox').textContent='Connected! IP: '+data.ip;"
"btn.textContent='Connected!';"
"}else{"
"document.getElementById('statusBox').className='status error';"
"document.getElementById('statusBox').textContent='Failed: '+data.error;"
"btn.disabled=false;"
"btn.textContent='Connect';"
"}"
"}).catch(e=>{"
"document.getElementById('statusBox').className='status error';"
"document.getElementById('statusBox').textContent='Error: '+e;"
"btn.disabled=false;"
"btn.textContent='Connect';"
"});"
"}"
"document.getElementById('password').addEventListener('keypress',e=>{if(e.key==='Enter')connectWifi();});"
"scanNetworks();"
"</script>"
"</body>"
"</html>";

/**
 * @brief HTTP handler for root page
 */
static esp_err_t http_root_handler(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, HTML_PAGE, strlen(HTML_PAGE));
    return ESP_OK;
}

/**
 * @brief HTTP handler for /scan endpoint
 */
static esp_err_t http_scan_handler(httpd_req_t *req)
{
    wifi_scan();
    
    cJSON *root = cJSON_CreateArray();
    
    for (int i = 0; i < ap_count; i++) {
        cJSON *network = cJSON_CreateObject();
        cJSON_AddStringToObject(network, "ssid", (char *)ap_records[i].ssid);
        cJSON_AddNumberToObject(network, "rssi", ap_records[i].rssi);
        cJSON_AddNumberToObject(network, "channel", ap_records[i].primary);
        cJSON_AddStringToObject(network, "auth", 
            ap_records[i].authmode == WIFI_AUTH_OPEN ? "Open" : "Secured");
        cJSON_AddItemToArray(root, network);
    }
    
    char *json_str = cJSON_PrintUnformatted(root);
    
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, json_str, strlen(json_str));
    
    free(json_str);
    cJSON_Delete(root);
    
    return ESP_OK;
}

/**
 * @brief HTTP handler for /connect endpoint
 */
static esp_err_t http_connect_handler(httpd_req_t *req)
{
    char buf[256];
    int ret, remaining = req->content_len;
    
    if (remaining > sizeof(buf) - 1) {
        remaining = sizeof(buf) - 1;
    }
    
    ret = httpd_req_recv(req, buf, remaining);
    if (ret <= 0) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }
    buf[ret] = '\0';
    
    cJSON *root = cJSON_Parse(buf);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
        return ESP_FAIL;
    }
    
    cJSON *ssid_json = cJSON_GetObjectItem(root, "ssid");
    cJSON *pass_json = cJSON_GetObjectItem(root, "password");
    
    if (!ssid_json || !cJSON_IsString(ssid_json)) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing SSID");
        return ESP_FAIL;
    }
    
    const char *ssid = ssid_json->valuestring;
    const char *password = pass_json && cJSON_IsString(pass_json) ? pass_json->valuestring : "";
    
    ESP_LOGI(TAG, "HTTP connect request - SSID: %s", ssid);
    
    cJSON *response = cJSON_CreateObject();
    
    if (wifi_connect_sta(ssid, password)) {
        /* Save credentials to NVS */
        nvs_save_wifi_credentials(ssid, password);
        
        /* Get the assigned IP */
        esp_netif_ip_info_t ip_info;
        esp_netif_get_ip_info(sta_netif, &ip_info);
        char ip_str[16];
        esp_ip4addr_ntoa(&ip_info.ip, ip_str, sizeof(ip_str));
        
        cJSON_AddBoolToObject(response, "success", true);
        cJSON_AddStringToObject(response, "ip", ip_str);
        
        /* Schedule stop of provisioning mode (after response is sent) */
        /* We'll do this in a separate task to allow HTTP response to be sent */
    } else {
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "error", "Connection failed");
    }
    
    char *response_str = cJSON_PrintUnformatted(response);
    
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, response_str, strlen(response_str));
    
    free(response_str);
    cJSON_Delete(response);
    cJSON_Delete(root);
    
    /* If connected, stop provisioning after a delay */
    if (sta_connected) {
        vTaskDelay(pdMS_TO_TICKS(1000));
        stop_provisioning_mode();
        start_csi_streaming();
    }
    
    return ESP_OK;
}

/**
 * @brief HTTP handler for /status endpoint
 */
static esp_err_t http_status_handler(httpd_req_t *req)
{
    cJSON *response = cJSON_CreateObject();
    
    if (sta_connected) {
        esp_netif_ip_info_t ip_info;
        esp_netif_get_ip_info(sta_netif, &ip_info);
        char ip_str[16];
        esp_ip4addr_ntoa(&ip_info.ip, ip_str, sizeof(ip_str));
        
        cJSON_AddStringToObject(response, "status", "connected");
        cJSON_AddStringToObject(response, "ip", ip_str);
    } else if (is_provisioning) {
        cJSON_AddStringToObject(response, "status", "provisioning");
    } else {
        cJSON_AddStringToObject(response, "status", "disconnected");
    }
    
    char *response_str = cJSON_PrintUnformatted(response);
    
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, response_str, strlen(response_str));
    
    free(response_str);
    cJSON_Delete(response);
    
    return ESP_OK;
}

/**
 * @brief Start HTTP server for provisioning
 */
static esp_err_t start_http_server(void)
{
    if (http_server) {
        ESP_LOGW(TAG, "HTTP server already running");
        return ESP_OK;
    }
    
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.server_port = HTTP_PORT;
    config.lru_purge_enable = true;
    
    ESP_LOGI(TAG, "Starting HTTP server on port %d", config.server_port);
    
    esp_err_t ret = httpd_start(&http_server, &config);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start HTTP server: %s", esp_err_to_name(ret));
        return ret;
    }
    
    /* Register URI handlers */
    httpd_uri_t root_uri = {
        .uri = "/",
        .method = HTTP_GET,
        .handler = http_root_handler,
    };
    httpd_register_uri_handler(http_server, &root_uri);
    
    httpd_uri_t scan_uri = {
        .uri = "/scan",
        .method = HTTP_GET,
        .handler = http_scan_handler,
    };
    httpd_register_uri_handler(http_server, &scan_uri);
    
    httpd_uri_t connect_uri = {
        .uri = "/connect",
        .method = HTTP_POST,
        .handler = http_connect_handler,
    };
    httpd_register_uri_handler(http_server, &connect_uri);
    
    httpd_uri_t status_uri = {
        .uri = "/status",
        .method = HTTP_GET,
        .handler = http_status_handler,
    };
    httpd_register_uri_handler(http_server, &status_uri);
    
    ESP_LOGI(TAG, "HTTP server started");
    return ESP_OK;
}

/**
 * @brief Stop HTTP server
 */
static void stop_http_server(void)
{
    if (http_server) {
        ESP_LOGI(TAG, "Stopping HTTP server");
        httpd_stop(http_server);
        http_server = NULL;
    }
}

/*===========================================================================*/
/*                          TCP PROVISIONING SERVER                           */
/*===========================================================================*/

/**
 * @brief Handle TCP client connection
 * 
 * Protocol:
 * - SCAN: Returns list of networks
 * - CONNECT ssid password: Connect to network
 * - STATUS: Return connection status
 * - RESET: Clear credentials and reboot
 */
static void handle_tcp_client(int sock)
{
    char rx_buffer[TCP_RX_BUF_SIZE];
    char tx_buffer[1024];
    
    while (is_provisioning) {
        int len = recv(sock, rx_buffer, sizeof(rx_buffer) - 1, 0);
        if (len < 0) {
            ESP_LOGE(TAG, "TCP recv error: errno %d", errno);
            break;
        } else if (len == 0) {
            ESP_LOGI(TAG, "TCP client disconnected");
            break;
        }
        
        rx_buffer[len] = '\0';
        
        /* Remove trailing newlines */
        while (len > 0 && (rx_buffer[len-1] == '\n' || rx_buffer[len-1] == '\r')) {
            rx_buffer[--len] = '\0';
        }
        
        ESP_LOGI(TAG, "TCP received: %s", rx_buffer);
        
        if (strncmp(rx_buffer, "SCAN", 4) == 0) {
            /* Scan for networks */
            wifi_scan();
            
            int offset = snprintf(tx_buffer, sizeof(tx_buffer), "OK %d\n", ap_count);
            for (int i = 0; i < ap_count && offset < sizeof(tx_buffer) - 100; i++) {
                offset += snprintf(tx_buffer + offset, sizeof(tx_buffer) - offset,
                    "%s,%d,%s\n",
                    ap_records[i].ssid,
                    ap_records[i].rssi,
                    ap_records[i].authmode == WIFI_AUTH_OPEN ? "Open" : "Secured");
            }
            
            send(sock, tx_buffer, strlen(tx_buffer), 0);
            
        } else if (strncmp(rx_buffer, "CONNECT ", 8) == 0) {
            /* Parse SSID and password (comma-separated to support SSIDs with spaces) */
            char *cmd = rx_buffer + 8;
            char *comma = strchr(cmd, ',');
            char ssid[MAX_SSID_LEN] = {0};
            char password[MAX_PASS_LEN] = {0};
            
            if (comma) {
                size_t ssid_len = comma - cmd;
                if (ssid_len >= MAX_SSID_LEN) ssid_len = MAX_SSID_LEN - 1;
                strncpy(ssid, cmd, ssid_len);
                strncpy(password, comma + 1, MAX_PASS_LEN - 1);
            } else {
                /* No comma - treat entire string as SSID (open network) */
                strncpy(ssid, cmd, MAX_SSID_LEN - 1);
            }
            
            ESP_LOGI(TAG, "TCP connect request - SSID: %s", ssid);
            
            if (wifi_connect_sta(ssid, password)) {
                /* Save credentials */
                nvs_save_wifi_credentials(ssid, password);
                
                esp_netif_ip_info_t ip_info;
                esp_netif_get_ip_info(sta_netif, &ip_info);
                char ip_str[16];
                esp_ip4addr_ntoa(&ip_info.ip, ip_str, sizeof(ip_str));
                
                snprintf(tx_buffer, sizeof(tx_buffer), "OK Connected %s\n", ip_str);
                send(sock, tx_buffer, strlen(tx_buffer), 0);
                
                /* Give client time to receive response, then stop provisioning */
                vTaskDelay(pdMS_TO_TICKS(500));
                close(sock);
                stop_provisioning_mode();
                start_csi_streaming();
                return;
            } else {
                snprintf(tx_buffer, sizeof(tx_buffer), "ERR Connection failed\n");
                send(sock, tx_buffer, strlen(tx_buffer), 0);
            }
            
        } else if (strncmp(rx_buffer, "STATUS", 6) == 0) {
            if (sta_connected) {
                esp_netif_ip_info_t ip_info;
                esp_netif_get_ip_info(sta_netif, &ip_info);
                char ip_str[16];
                esp_ip4addr_ntoa(&ip_info.ip, ip_str, sizeof(ip_str));
                snprintf(tx_buffer, sizeof(tx_buffer), "OK CONNECTED %s\n", ip_str);
            } else if (is_provisioning) {
                snprintf(tx_buffer, sizeof(tx_buffer), "OK PROVISIONING\n");
            } else {
                snprintf(tx_buffer, sizeof(tx_buffer), "OK DISCONNECTED\n");
            }
            send(sock, tx_buffer, strlen(tx_buffer), 0);
            
        } else if (strncmp(rx_buffer, "RESET", 5) == 0) {
            nvs_clear_wifi_credentials();
            snprintf(tx_buffer, sizeof(tx_buffer), "OK Rebooting...\n");
            send(sock, tx_buffer, strlen(tx_buffer), 0);
            vTaskDelay(pdMS_TO_TICKS(500));
            esp_restart();
            
        } else {
            snprintf(tx_buffer, sizeof(tx_buffer), 
                "ERR Unknown command. Available: SCAN, CONNECT <ssid>,<password>, STATUS, RESET\n");
            send(sock, tx_buffer, strlen(tx_buffer), 0);
        }
    }
    
    close(sock);
}

/**
 * @brief TCP provisioning server task
 */
void tcp_provision_task(void *pvParameters)
{
    struct sockaddr_in server_addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_ANY),
        .sin_port = htons(TCP_PROVISION_PORT),
    };
    
    int listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (listen_sock < 0) {
        ESP_LOGE(TAG, "TCP: Failed to create socket: errno %d", errno);
        vTaskDelete(NULL);
        return;
    }
    
    int opt = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    if (bind(listen_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        ESP_LOGE(TAG, "TCP: Failed to bind: errno %d", errno);
        close(listen_sock);
        vTaskDelete(NULL);
        return;
    }
    
    if (listen(listen_sock, 1) < 0) {
        ESP_LOGE(TAG, "TCP: Failed to listen: errno %d", errno);
        close(listen_sock);
        vTaskDelete(NULL);
        return;
    }
    
    ESP_LOGI(TAG, "TCP provisioning server listening on port %d", TCP_PROVISION_PORT);
    
    /* Set socket to non-blocking for clean shutdown */
    struct timeval timeout = { .tv_sec = 1, .tv_usec = 0 };
    setsockopt(listen_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    
    while (is_provisioning) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        
        int client_sock = accept(listen_sock, (struct sockaddr *)&client_addr, &addr_len);
        if (client_sock < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;  /* Timeout, check if still provisioning */
            }
            ESP_LOGE(TAG, "TCP: Accept failed: errno %d", errno);
            continue;
        }
        
        char addr_str[16];
        inet_ntoa_r(client_addr.sin_addr, addr_str, sizeof(addr_str));
        ESP_LOGI(TAG, "TCP: Client connected from %s", addr_str);
        
        /* Send welcome message */
        const char *welcome = "ESP32 CSI Provisioning Server\nCommands: SCAN, CONNECT <ssid>,<password>, STATUS, RESET\n";
        send(client_sock, welcome, strlen(welcome), 0);
        
        handle_tcp_client(client_sock);
    }
    
    close(listen_sock);
    ESP_LOGI(TAG, "TCP provisioning server stopped");
    vTaskDelete(NULL);
}

/*===========================================================================*/
/*                          TASK FUNCTIONS                                    */
/*===========================================================================*/

/**
 * @brief CSI Streaming Task
 */
void csi_stream_task(void *pvParameters)
{
    const size_t required_buffer_size = sizeof(packet_t) + sizeof(csi_payload_t);
    uint8_t buffer[required_buffer_size + 16];
    
    udp_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (udp_sock < 0) {
        ESP_LOGE(TAG, "CSI: Unable to create UDP socket: errno %d", errno);
        vTaskDelete(NULL);
        return;
    }
    ESP_LOGI(TAG, "CSI: UDP socket created for streaming");
    
    /* Enable broadcast */
    int broadcast = 1;
    setsockopt(udp_sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));
    
    memset(&csi_dest_addr, 0, sizeof(csi_dest_addr));
    csi_dest_addr.sin_family = AF_INET;
    csi_dest_addr.sin_port = htons(UDP_CSI_PORT);
    
    if (strcmp(CSI_DEST_IP_ADDR, "255.255.255.255") == 0) {
        csi_dest_addr.sin_addr.s_addr = INADDR_BROADCAST;
    } else {
        csi_dest_addr.sin_addr.s_addr = inet_addr(CSI_DEST_IP_ADDR);
    }
    
    ESP_LOGI(TAG, "CSI: Streaming to %s:%d (rate limit: %d ms)", 
             CSI_DEST_IP_ADDR, UDP_CSI_PORT, CSI_MIN_INTERVAL_MS);
    
    uint32_t sent_count = 0;
    int64_t last_stats_time = esp_timer_get_time();
    const int64_t STATS_INTERVAL_US = 5000000;
    
    while (1) {
        size_t item_size;
        
        int64_t now = esp_timer_get_time();
        if ((now - last_stats_time) >= STATS_INTERVAL_US) {
            float elapsed_sec = (now - last_stats_time) / 1000000.0f;
            ESP_LOGI(TAG, "CSI Stats: sent=%lu, captured=%lu, dropped=%lu, rate=%.1f pkt/s",
                     sent_count, csi_captured_count, csi_dropped_count,
                     sent_count / elapsed_sec);
            sent_count = 0;
            last_stats_time = now;
        }
        
        csi_payload_t *payload = (csi_payload_t *)xRingbufferReceive(
            csi_ringbuf, &item_size, pdMS_TO_TICKS(100));
        
        if (payload) {
            if (item_size != sizeof(csi_payload_t)) {
                vRingbufferReturnItem(csi_ringbuf, payload);
                continue;
            }
            
            packet_t *pkt = (packet_t *)buffer;
            pkt->magic = htons(PKT_MAGIC);
            pkt->version = 1;
            pkt->type = PKT_TYPE_CSI;
            pkt->seq = htonl(packet_seq++);
            pkt->timestamp = payload->timestamp;
            pkt->payload_len = htons(sizeof(csi_payload_t));
            memcpy(pkt->payload, payload, sizeof(csi_payload_t));
            
            int sent = sendto(udp_sock, buffer, required_buffer_size, 0,
                             (struct sockaddr *)&csi_dest_addr, sizeof(csi_dest_addr));
            
            if (sent > 0) {
                sent_count++;
            }
            
            vRingbufferReturnItem(csi_ringbuf, payload);
        }
    }
    
    close(udp_sock);
    vTaskDelete(NULL);
}

/**
 * @brief Traffic Generator Task
 */
void traffic_generator_task(void *pvParameters)
{
    ESP_LOGI(TAG, "Traffic generator started (interval: %d ms)", TRAFFIC_GEN_INTERVAL_MS);
    
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock < 0) {
        ESP_LOGE(TAG, "Traffic gen: Unable to create socket: errno %d", errno);
        vTaskDelete(NULL);
        return;
    }
    
    esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    esp_netif_ip_info_t ip_info;
    
    if (netif == NULL || esp_netif_get_ip_info(netif, &ip_info) != ESP_OK) {
        ESP_LOGE(TAG, "Traffic gen: Failed to get IP info");
        close(sock);
        vTaskDelete(NULL);
        return;
    }
    
    struct sockaddr_in dest_addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = ip_info.gw.addr,
        .sin_port = htons(12345),
    };
    
    char gw_str[16];
    esp_ip4addr_ntoa(&ip_info.gw, gw_str, sizeof(gw_str));
    ESP_LOGI(TAG, "Traffic gen: Sending to gateway %s", gw_str);
    
    uint8_t ping_data[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    
    while (1) {
        sendto(sock, ping_data, sizeof(ping_data), 0,
               (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        vTaskDelay(pdMS_TO_TICKS(TRAFFIC_GEN_INTERVAL_MS));
    }
    
    close(sock);
    vTaskDelete(NULL);
}

/*===========================================================================*/
/*                          MAIN ENTRY POINT                                  */
/*===========================================================================*/

/**
 * @brief Application entry point
 */
void app_main(void)
{
    ESP_LOGI(TAG, "========================================");
    ESP_LOGI(TAG, "ESP32 CSI Streaming with WiFi Provisioning");
    ESP_LOGI(TAG, "========================================");
    
    /* Create CSI ring buffer */
    const size_t ringbuf_size = 10 * sizeof(csi_payload_t);
    csi_ringbuf = xRingbufferCreate(ringbuf_size, RINGBUF_TYPE_NOSPLIT);
    if (csi_ringbuf == NULL) {
        ESP_LOGE(TAG, "Failed to create CSI ring buffer");
        return;
    }
    ESP_LOGI(TAG, "CSI ring buffer created (%d bytes)", ringbuf_size);
    
    /* Initialize WiFi in APSTA mode */
    wifi_init_apsta();
    
    /* Try to load saved credentials */
    char saved_ssid[MAX_SSID_LEN] = {0};
    char saved_pass[MAX_PASS_LEN] = {0};
    
    if (nvs_load_wifi_credentials(saved_ssid, saved_pass) == ESP_OK) {
        ESP_LOGI(TAG, "Found saved credentials, attempting auto-connect...");
        
        if (wifi_connect_sta(saved_ssid, saved_pass)) {
            ESP_LOGI(TAG, "Auto-connect successful!");
            
            /* Switch to STA-only mode and start CSI */
            wifi_switch_to_sta_only();
            start_csi_streaming();
            
            /* Main loop - just keep running */
            while (1) {
                vTaskDelay(pdMS_TO_TICKS(10000));
            }
        } else {
            ESP_LOGW(TAG, "Auto-connect failed, starting provisioning mode...");
        }
    }
    
    /* No saved credentials or auto-connect failed - start provisioning */
    start_provisioning_mode();
    
    /* Main loop - provisioning mode */
    while (1) {
        /* Check if we've connected via provisioning */
        if (sta_connected && !is_provisioning) {
            ESP_LOGI(TAG, "Connected via provisioning, CSI streaming active");
        }
        vTaskDelay(pdMS_TO_TICKS(5000));
    }
}
