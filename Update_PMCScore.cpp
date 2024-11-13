#include <cstdio>
#include <cstring>
#include <string>
#include <curl/curl.h>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>  // 使用 nlohmann/json 库
#include <openssl/evp.h>
#include <openssl/err.h>
#include <filesystem>

using namespace std;
using json = nlohmann::json;
namespace fs = std::filesystem;

// 回调函数，用于写入 cURL 请求的响应
static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

// 写入文件内容的回调函数
static size_t FileWriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t newLength = size * nmemb;
    ofstream* s = (ofstream*)userp;
    s->write((char*)contents, newLength);
    return newLength;
}

// 计算文件的 SHA-256 哈希
string sha256_file(const string& filepath) {
    EVP_MD_CTX* mdctx = nullptr;
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    FILE* file = nullptr;
    const char* filename = filepath.c_str();
    char buffer[1024];
    size_t bytes;

    mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        ERR_print_errors_fp(stderr);
        throw runtime_error("无法创建 EVP_MD_CTX");
    }

    if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr)) {
        EVP_MD_CTX_free(mdctx);
        ERR_print_errors_fp(stderr);
        throw runtime_error("无法初始化 SHA-256");
    }

    file = fopen(filename, "rb");
    if (!file) {
        EVP_MD_CTX_free(mdctx);
        ERR_print_errors_fp(stderr);
        throw runtime_error("无法打开文件");
    }

    while ((bytes = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (1 != EVP_DigestUpdate(mdctx, buffer, bytes)) {
            fclose(file);
            EVP_MD_CTX_free(mdctx);
            ERR_print_errors_fp(stderr);
            throw runtime_error("无法更新 SHA-256");
        }
    }

    if (1 != EVP_DigestFinal_ex(mdctx, hash, &len)) {
        fclose(file);
        EVP_MD_CTX_free(mdctx);
        ERR_print_errors_fp(stderr);
        throw runtime_error("无法完成 SHA-256");
    }

    fclose(file);
    EVP_MD_CTX_free(mdctx);

    char ss[EVP_MAX_MD_SIZE * 2 + 1];
    for (unsigned int i = 0; i < len; i++) {
        sprintf(ss + i * 2, "%02x", hash[i]);
    }
    return string(ss);
}

// 从指定 URL 获取 JSON 响应
json fetch_json(const string& url) {
    CURL* curl;
    CURLcode res;
    string readBuffer;

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() 失败: %s\n", curl_easy_strerror(res));
        }
        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();
    return json::parse(readBuffer);
}

// 下载文件
void download_file(const string& url, const string& filename) {
    CURL* curl;
    CURLcode res;
    ofstream file(filename, ofstream::binary);

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, FileWriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &file);
        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() 失败: %s\n", curl_easy_strerror(res));
        }
        file.close();
        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();
}

// 删除旧版本 .jar 文件
void delete_old_versions(const string& directory, const string& current_version) {
    for (const auto& entry : fs::directory_iterator(directory)) {
        string filename = entry.path().filename().string();

        // 只删除以 "paper-1.21.3-" 开头且扩展名为 .jar 的文件
        if (filename.find("paper-1.21.3-") != string::npos && filename != current_version &&
            entry.path().extension() == ".jar") {
            cout << "删除旧版本文件: " << filename << endl;
            fs::remove(entry.path());
        }
    }
}

int main() {
    string apiUrl = "https://api.papermc.io/v2/projects/paper/versions/1.21.3/builds/";
    json apiResponse = fetch_json(apiUrl);

    if (apiResponse.contains("builds") && !apiResponse["builds"].empty()) {
        // 获取最新的构建号和对应的哈希值
        auto latestBuild = apiResponse["builds"].back();
        int buildNumber = latestBuild["build"].get<int>();
        string fileHash = latestBuild["downloads"]["application"]["sha256"].get<string>();

        // 设置文件名和下载 URL
        string filename = "paper-1.21.3-" + to_string(buildNumber) + ".jar";
        string downloadUrl = apiUrl + to_string(buildNumber) + "/downloads/paper-1.21.3-" + to_string(buildNumber) + ".jar";

        // 删除旧版本文件
        delete_old_versions(".", filename);

        // 检查文件是否已经存在
        if (fs::exists(filename)) {
            printf("文件已存在。正在检查哈希...\n");
            string existingHash = sha256_file(filename);
            
            if (existingHash == fileHash) {
                printf("文件已是最新，无需下载。\n");
                return 0;
            } else {
                printf("文件已过期。正在删除旧文件...\n");
                fs::remove(filename);
            }
        }

        // 下载文件并校验哈希
        download_file(downloadUrl, filename);
        string downloadedHash = sha256_file(filename);
        if (downloadedHash == fileHash) {
            printf("下载的文件验证成功。\n");
        } else {
            fprintf(stderr, "哈希不匹配！下载的文件可能已损坏。\n");
        }
    } else {
        fprintf(stderr, "API 响应中未找到构建信息。\n");
    }

    return 0;
}
