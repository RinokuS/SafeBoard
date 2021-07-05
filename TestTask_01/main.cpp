#include <iostream>
#include <fstream>
#include <filesystem>
#include <vector>
#include <algorithm>

#include "profile.h"

using namespace std;

struct suspicious_counter {
    long long js_counter = 0;
    long long unix_counter = 0;
    long long mac_counter = 0;
    long long error_counter = 0;
};

/// Метод для получения массива файлов, лежащих в заданной директории (с использованием filesystem)
/// \param directory_path путь до директории
/// \return вектор объектов типа path
vector<filesystem::path> get_files_from_directory(const string &directory_path) {
    auto it = filesystem::directory_iterator(directory_path);

    vector<filesystem::path> regular_files;
    copy_if(filesystem::begin(it), filesystem::end(it), std::back_inserter(regular_files),
                 [](const auto& entry) {
                     return filesystem::is_regular_file(entry);
                 });

    return regular_files;
}

/// Метод для проверки файла
/// \param file_name полный путь к файлу с именем
/// \param extension расширение файла
/// \param s_counter общий счетчик ошибок, дабы не заводить глобальные переменные
void check_file(const string &file_name, const string &extension, suspicious_counter &s_counter) {
    ifstream is(file_name);
    string line;
    bool is_sus_js = false; // переменные для обнаружения ошибки в конкретном файле
    bool is_sus_unix = false;
    bool is_sus_mac = false;

    if (is) {
        // В задании не совсем понятно, "содержащий строку" означает, что файл содержит строку или же
        // что в любой строке файла может быть ее вхождение, так что выбрана первая интерпретация
        while (std::getline(is, line)) {
            if (!is_sus_js && line == "<script>evil_script()</script>" && extension == ".js")
                is_sus_js = true;
            else if (!is_sus_unix && line == "rm -rf ~/Documents")
                is_sus_unix = true;
            else if (!is_sus_mac && line == "system(\"launchctl load /Library/LaunchAgents/com.malware.agent\")")
                is_sus_mac = true;
        }

        if (is_sus_js)
            s_counter.js_counter++;
        if (is_sus_unix)
            s_counter.unix_counter++;
        if (is_sus_mac)
            s_counter.mac_counter++;
    } else { // если файл не открылся - записываем в счетчик ошибок
        s_counter.error_counter++;
    }
}

/// Метод для вывода информации о работе программы в консоль
/// \param number_of_files количество обычных файлов в директории
/// \param s_counter общий счетчик ошибок
void print_info(size_t number_of_files, const suspicious_counter &s_counter) {
    cout << "====== Scan result ======\n" <<
    "Processed files: " << number_of_files << '\n' <<
    "JS detects: " << s_counter.js_counter << '\n' <<
    "Unix detects: " << s_counter.unix_counter << '\n' <<
    "macOS detects: " << s_counter.mac_counter << '\n' <<
    "Errors: " << s_counter.error_counter << '\n';
}

int main(int argc, char *argv[]) {
    if (argc <= 1) {
        cout << "Please, pass the directory path to the program arguments\n";

        return 1;
    }
    LOG_DURATION("Execution time") // макрос для подсчета времени выполнения
    try {
        auto files_in_directory = get_files_from_directory(argv[1]);
        suspicious_counter s_counter;

        for (const auto &file: files_in_directory)
            check_file(file.string(), file.extension(), s_counter);

        print_info(files_in_directory.size(), s_counter);
    } catch (filesystem::filesystem_error &e) {
        cout << "Wrong directory path!\n" << e.what() << '\n';
    }

    return 0;
}
