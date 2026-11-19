#include "quark/config.hpp"

#include <fstream>

namespace quark::config {

namespace {

std::string Trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return {};
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

}  // namespace

std::optional<Config> Config::Load(const std::string& path) {
    std::ifstream in(path);
    if (!in) return std::nullopt;

    Config cfg;
    std::string line;
    while (std::getline(in, line)) {
        std::string trimmed = Trim(line);
        if (trimmed.empty() || trimmed[0] == '#') continue;

        size_t eq = trimmed.find('=');
        if (eq == std::string::npos) continue;  // malformed line -- skip, don't fail the whole file

        std::string key = Trim(trimmed.substr(0, eq));
        std::string value = Trim(trimmed.substr(eq + 1));
        if (key.empty()) continue;
        cfg.values_[key] = value;
    }
    return cfg;
}

std::string Config::GetOr(const std::string& key, const std::string& fallback) const {
    auto it = values_.find(key);
    return it != values_.end() ? it->second : fallback;
}

int Config::GetIntOr(const std::string& key, int fallback) const {
    auto it = values_.find(key);
    if (it == values_.end()) return fallback;
    try {
        size_t consumed = 0;
        int value = std::stoi(it->second, &consumed);
        if (consumed != it->second.size()) return fallback;  // trailing garbage, e.g. "30000ms"
        return value;
    } catch (...) {
        return fallback;
    }
}

}  // namespace quark::config
