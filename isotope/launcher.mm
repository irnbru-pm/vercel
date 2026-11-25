// The helper authenticates this executable. Only the bundled child inherits
// the credential socket. The Go worker is never an XPC peer.
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <mach-o/dyld.h>
#import <xpc/xpc.h>
#include <spawn.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
#include <limits.h>
#include <vector>

static bool transfer(int fd, void *ptr, size_t length, bool sending) {
    auto bytes = static_cast<char *>(ptr);
    while (length) {
        ssize_t count = sending ? write(fd, bytes, length) : read(fd, bytes, length);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        bytes += count; length -= count;
    }
    return true;
}

static bool signedBundle(NSString *path) {
    SecStaticCodeRef code = nullptr;
    SecRequirementRef rule = nullptr;
    NSURL *url = [NSURL fileURLWithPath:path];
    bool ok = SecStaticCodeCreateWithPath((__bridge CFURLRef)url, kSecCSDefaultFlags, &code) == errSecSuccess &&
        SecRequirementCreateWithString(CFSTR("anchor apple generic and identifier \"dev.mxcl.irnbru." TOOL "\" and certificate leaf[subject.OU] = ZU76A67LGU"), kSecCSDefaultFlags, &rule) == errSecSuccess &&
        SecStaticCodeCheckValidity(code, kSecCSStrictValidate | kSecCSCheckNestedCode, rule) == errSecSuccess;
    if (code) CFRelease(code);
    if (rule) CFRelease(rule);
    return ok;
}
static bool installed(NSString *executable) {
    NSRange match = [executable rangeOfString:@"^/opt/bru/pkg/" TOOL "/[0-9a-f]{64}/" BUNDLE "\\.app/Contents/MacOS/" TOOL "$" options:NSRegularExpressionSearch];
    if (match.location == NSNotFound) return false;
    for (NSString *part = executable; part.length > 1; part = part.stringByDeletingLastPathComponent) {
        struct stat st;
        if (lstat(part.fileSystemRepresentation, &st) || st.st_uid != 0 || (st.st_mode & 022) || S_ISLNK(st.st_mode)) return false;
    }
    return true;
}

static NSData *exchange(NSData *payload) {
    const char *service = "dev.mxcl.irnbru." TOOL "-approval";
    xpc_connection_t peer = xpc_connection_create_mach_service(service, nullptr, 0);
    const char *rule = "anchor apple generic and identifier \"dev.mxcl.irnbru.helper\" and certificate leaf[subject.OU] = ZU76A67LGU and ! entitlement[\"com.apple.security.get-task-allow\"] exists";
    if (!peer || xpc_connection_set_peer_code_signing_requirement(peer, rule)) return nil;
    xpc_connection_set_event_handler(peer, ^(xpc_object_t event) {
        if (xpc_get_type(event) == XPC_TYPE_DICTIONARY && xpc_dictionary_get_bool(event, "review")) fprintf(stderr, "IrnBru: human approval required\n");
    });
    xpc_connection_activate(peer);
    xpc_object_t message = xpc_dictionary_create_empty();
    xpc_dictionary_set_data(message, "request", payload.bytes, payload.length);
    xpc_object_t reply = xpc_connection_send_message_with_reply_sync(peer, message);
    xpc_connection_cancel(peer);
    if (!reply || xpc_get_type(reply) != XPC_TYPE_DICTIONARY) return nil;
    size_t count = 0;
    const void *data = xpc_dictionary_get_data(reply, "response", &count);
    return data && count && count <= 256 * 1024 ? [NSData dataWithBytes:data length:count] : nil;
}

int main(int argc, char **argv) {
    @autoreleasepool {
        struct rlimit core = {0, 0};
        if (setrlimit(RLIMIT_CORE, &core)) return 1;
        char path[PATH_MAX], canonical[PATH_MAX]; uint32_t size = sizeof(path);
        if (_NSGetExecutablePath(path, &size) || !realpath(path, canonical)) return 1;
        NSString *executable = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:canonical length:strlen(canonical)];
        NSString *contents = executable.stringByDeletingLastPathComponent.stringByDeletingLastPathComponent;
        if (!signedBundle(contents.stringByDeletingLastPathComponent)) { fprintf(stderr, "Invalid Isotope signature\n"); return 1; }
        NSString *worker = [contents stringByAppendingPathComponent:@"Helpers/worker"];
        std::vector<const char *> args = {worker.fileSystemRepresentation};
        NSString *entry = [contents stringByAppendingPathComponent:@"Resources/vercel/dist/index.js"];
        args.push_back("--no-global-search-paths");
        args.push_back("--");
        args.push_back(entry.fileSystemRepresentation);
        for (int i=1; i<argc; ++i) args.push_back(argv[i]);
        args.push_back(nullptr);
        NSString *home = NSHomeDirectory();
        NSString *homeEnv = [@"HOME=" stringByAppendingString:home];
        std::vector<const char *> env = {"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=en_US.UTF-8", homeEnv.fileSystemRepresentation};
        if (const char *value = getenv("VERCEL_TOKEN")) env.push_back([[NSString stringWithFormat:@"VERCEL_TOKEN=%s", value] UTF8String]);

        env.push_back(nullptr);
        for (int fd = 0; fd < 3; ++fd) {
            if (fcntl(fd, F_GETFD) < 0 && open("/dev/null", O_RDWR) != fd) return 1;
        }
        int pair[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair)) return 1;
        int one = 1;
        setsockopt(pair[0], SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
        posix_spawn_file_actions_t actions; posix_spawnattr_t attr;
        if (posix_spawn_file_actions_init(&actions) || posix_spawnattr_init(&attr) ||
            posix_spawnattr_setflags(&attr, POSIX_SPAWN_CLOEXEC_DEFAULT) ||
            posix_spawn_file_actions_adddup2(&actions, pair[1], 3)) return 1;
        for (int fd=0; fd<3; fd++) if (fcntl(fd,F_GETFD) >= 0 && posix_spawn_file_actions_addinherit_np(&actions,fd)) return 1;
        pid_t child;
        int status = posix_spawn(&child,worker.fileSystemRepresentation,&actions,&attr,const_cast<char **>(args.data()),const_cast<char **>(env.data()));
        posix_spawn_file_actions_destroy(&actions); posix_spawnattr_destroy(&attr); close(pair[1]);
        if (status) { fprintf(stderr,"Could not start the signed CLI worker (%d)\n",status); return 1; }
        uint32_t length;
        while (transfer(pair[0], &length, sizeof(length), false)) { @autoreleasepool {
            size_t count = ntohl(length);
            if (!count || count > 256 * 1024) break;
            NSMutableData *request = [NSMutableData dataWithLength:count];
            if (!transfer(pair[0], request.mutableBytes, count, false)) break;
            NSData *reply = installed(executable) ? exchange(request) : nil;
            if (!reply) reply = [@"{\"ok\":false,\"error\":\"Install the signed CLI and start the compatible IrnBru helper.\"}" dataUsingEncoding:NSUTF8StringEncoding];
            length = htonl((uint32_t)reply.length);
            if (!transfer(pair[0], &length, sizeof(length), true) || !transfer(pair[0], (void *)reply.bytes, reply.length, true)) break;
        }}
        close(pair[0]);
        while (waitpid(child, &status, 0) < 0) if (errno != EINTR) return 1;
        return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
    }
}
