#include "quark/platform/hwid_json.hpp"

#include <sstream>

namespace quark::platform {

namespace {

std::string JsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        if (c == '"' || c == '\\') out.push_back('\\');
        out.push_back(c);
    }
    return out;
}

// Finds the next `"key": "value"` pair at or after `pos`, honoring the same
// escaping FieldToJson produces (\" and \\ only -- no unicode escapes, this
// is not a general JSON parser). Returns the byte offset just past the
// closing quote of the value, or std::string::npos on failure.
std::optional<std::pair<std::string, std::string>> ParseNextStringField(
    const std::string& json, size_t start, size_t* end_out) {
    size_t key_start = json.find('"', start);
    if (key_start == std::string::npos) return std::nullopt;
    size_t key_end = json.find('"', key_start + 1);
    if (key_end == std::string::npos) return std::nullopt;
    std::string key = json.substr(key_start + 1, key_end - key_start - 1);

    size_t colon = json.find(':', key_end);
    if (colon == std::string::npos) return std::nullopt;
    size_t val_start = json.find('"', colon);
    if (val_start == std::string::npos) return std::nullopt;

    std::string value;
    size_t i = val_start + 1;
    while (i < json.size() && json[i] != '"') {
        if (json[i] == '\\' && i + 1 < json.size()) ++i;
        value.push_back(json[i]);
        ++i;
    }
    if (i >= json.size()) return std::nullopt;
    *end_out = i + 1;
    return std::make_pair(key, value);
}

}  // namespace

std::string FingerprintToJson(const std::string& platform_name, const Fingerprint& fp) {
    std::ostringstream oss;
    oss << "{\n  \"platform\": \"" << JsonEscape(platform_name) << "\",\n  \"fields\": [\n";
    for (size_t i = 0; i < fp.fields.size(); ++i) {
        oss << "    {\"name\": \"" << JsonEscape(fp.fields[i].name)
            << "\", \"value\": \"" << JsonEscape(fp.fields[i].value) << "\"}";
        if (i + 1 != fp.fields.size()) oss << ',';
        oss << '\n';
    }
    oss << "  ]\n}\n";
    return oss.str();
}

std::optional<ParsedFingerprint> FingerprintFromJson(const std::string& json) {
    size_t platform_pos = json.find("\"platform\"");
    if (platform_pos == std::string::npos) return std::nullopt;
    size_t end = 0;
    auto platform_field = ParseNextStringField(json, platform_pos, &end);
    if (!platform_field) return std::nullopt;

    size_t fields_pos = json.find("\"fields\"", end);
    if (fields_pos == std::string::npos) return std::nullopt;
    size_t array_start = json.find('[', fields_pos);
    if (array_start == std::string::npos) return std::nullopt;
    size_t array_end = json.find(']', array_start);
    if (array_end == std::string::npos) return std::nullopt;

    ParsedFingerprint result;
    result.platform_name = platform_field->second;

    size_t pos = array_start + 1;
    while (pos < array_end) {
        size_t name_search_end = 0;
        size_t brace = json.find('{', pos);
        if (brace == std::string::npos || brace >= array_end) break;

        auto name_field = ParseNextStringField(json, brace, &name_search_end);
        if (!name_field || name_field->first != "name") return std::nullopt;

        size_t value_search_end = 0;
        auto value_field = ParseNextStringField(json, name_search_end, &value_search_end);
        if (!value_field || value_field->first != "value") return std::nullopt;

        result.fingerprint.fields.push_back({name_field->second, value_field->second});
        pos = value_search_end;
    }

    if (result.fingerprint.fields.empty()) return std::nullopt;
    return result;
}

}  // namespace quark::platform
