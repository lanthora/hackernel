#include "file/audit.h"
#include "hackernel/ipc.h"
#include "hackernel/json.h"
#include "hackernel/threads.h"
#include "hackernel/timer.h"
#include "hackernel/util.h"
#include <fstream>

namespace hackernel {

namespace file {

Auditor &Auditor::GetInstance() {
    static Auditor instance;
    return instance;
}

Auditor::Auditor() {}

Auditor::~Auditor() {
    Save();
}

void Auditor::MarkChanged() {
    last_update_time_ = std::chrono::system_clock::now();
}

int Auditor::Save() {
    std::lock_guard<std::mutex> lock(sl_mutex_);

    static auto last_save_time = std::chrono::system_clock::now();
    if (last_save_time == last_update_time_)
        return 0;

    std::error_code ec;
    std::filesystem::create_directories("/var/lib/hackernel", ec);
    if (ec) {
        WARN("create dir /var/lib/hackernel failed, errmsg=[%s]", ec.message().data());
        return -EPERM;
    }

    std::ofstream output("/var/lib/hackernel/file.json");
    if (!output) {
        WARN("open /var/lib/hackernel/file.json failed");
        return -EPERM;
    }
    nlohmann::json doc;
    std::shared_lock<std::shared_mutex> perms_lock(perms_mutex_);
    for (const auto &it : perms_) {
        nlohmann::json element;
        element["file"] = it.first;
        element["perm"] = it.second;
        doc["perms"].push_back(element);
    }

    doc["enabled"] = enabled_;

    // TODO: 验证写入非UTF-8编码字符时是否出现异常
    output << std::setw(4) << doc;
    output.close();

    last_save_time = last_update_time_;
    return 0;
}

int Auditor::Load() {
    std::lock_guard<std::mutex> lock(sl_mutex_);

    std::ifstream input("/var/lib/hackernel/file.json");
    if (!input) {
        WARN("open /var/lib/hackernel/file.json failed.");
        return -EINVAL;
    }

    nlohmann::json doc;
    try {
        input >> doc;
    } catch (nlohmann::json::parse_error &ex) {
        WARN("parse error");
    }
    input.close();

    if (!doc.is_object()) {
        WARN("file.json is not json");
        return -EINVAL;
    }

    if (doc["enabled"].is_boolean()) {
        enabled_ = doc["enabled"];
    }

    std::unique_lock<std::shared_mutex> perms_lock(perms_mutex_);
    for (const auto &element : doc["perms"]) {
        if (!element["file"].is_string() || !element["perm"].is_number_integer()) {
            WARN("element parse failed, element=[%s]", json::dump(element).data());
            continue;
        }
        perms_[element["file"]] = element["perm"];
    }
    return 0;
}

// 自我防护设置,每次启动都会生效,除非用户运行过程中强行解除防护
int Auditor::InitDefender() {
    std::unique_lock<std::shared_mutex> perms_lock(perms_mutex_);
    perms_["/tmp"] = FLAG_FILE_DISABLE_RENAME;
    perms_["/tmp/hackernel.sock"] = FLAG_FILE_DISABLE_RENAME | FLAG_FILE_DISABLE_DELETE;
    perms_["/var"] = FLAG_FILE_DISABLE_RENAME;
    perms_["/var/lib"] = FLAG_FILE_DISABLE_RENAME;
    perms_["/var/lib/hackernel"] = FLAG_FILE_DISABLE_ALL;
    MarkChanged();
    return 0;
}

int Auditor::Init() {

    receiver_ = std::make_shared<Receiver>();
    if (!receiver_) {
        ERR("make receiver failed");
        return -ENOMEM;
    }
    receiver_->AddHandler([&](const std::string &msg) { return Handler(msg); });
    Broadcaster::GetInstance().AddReceiver(receiver_);
    Threads::GetInstance().AddThread([&]() {
        ThreadNameUpdate("file");
        receiver_->ConsumeWait();
    });

    Load();
    SetAutoSaveTimer();

    if (enabled_) {
        FileProtectEnable(SYSTEM_SESSION);
    }

    InitDefender();

    std::shared_lock<std::shared_mutex> perms_lock(perms_mutex_);
    for (const auto &element : perms_) {
        FileProtectSet(SYSTEM_SESSION, element.first.data(), element.second);
    }

    return 0;
}

int Auditor::SetAutoSaveTimer() {
    timer::Element element;
    element.time_point = std::chrono::system_clock::now() + std::chrono::minutes(1);
    element.func = [&]() {
        Save();
        SetAutoSaveTimer();
    };
    timer::Timer::GetInstance().Insert(element);
    return 0;
}

bool Auditor::Handler(const std::string &msg) {
    nlohmann::json doc = json::parse(msg);
    if (doc["type"] == "user::file::enable") {
        enabled_ = true;
        MarkChanged();

        std::shared_lock<std::shared_mutex> perms_lock(perms_mutex_);
        for (const auto &element : perms_) {
            FileProtectSet(SYSTEM_SESSION, element.first.data(), element.second);
        }

        return true;
    }
    if (doc["type"] == "user::file::disable") {
        enabled_ = false;
        MarkChanged();
        return true;
    }
    if (doc["type"] == "user::file::set") {

        const std::string path = doc["data"]["path"];
        const FilePerm perm = doc["data"]["perm"];

        std::unique_lock<std::shared_mutex> perms_lock(perms_mutex_);

        if (perm) {
            perms_[path] = perm;
        } else {
            perms_.erase(path);
        }

        MarkChanged();
        return true;
    }

    return false;
}

} // namespace file

} // namespace hackernel
