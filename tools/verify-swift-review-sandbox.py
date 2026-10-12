#!/usr/bin/env python3
"""macOS-only local confinement probe. Does not contact a remote service."""
import json
from pathlib import Path
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parent.parent
runner = (root / "src/checks/runner.rs").read_text()
profile = json.loads(re.search(r'const PROFILE: &str = (".*");', runner)[1])
with tempfile.TemporaryDirectory(prefix="acp-review-sandbox-", dir="/private/tmp") as folder:
    folder = Path(folder)
    source = folder / "probe.c"
    helper = folder / "probe"
    secret = folder / "fixture-secret"
    output = folder / "must-not-exist"
    secret.write_text("local test fixture, not a credential")
    source.write_text(r'''
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc != 3) return 2;
    errno = 0; int fd = open(argv[1], O_RDONLY); int rd = errno;
    if (fd >= 0) { close(fd); return 3; }
    errno = 0; fd = open(argv[2], O_WRONLY | O_CREAT, 0600); int wr = errno;
    if (fd >= 0) { close(fd); return 4; }
    errno = 0; int socketFD = socket(AF_INET, SOCK_STREAM, 0); int net = errno;
    if (socketFD >= 0) {
        struct sockaddr_in address = {0};
        address.sin_family = AF_INET; address.sin_port = htons(1);
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        errno = 0; connect(socketFD, (struct sockaddr *)&address, sizeof(address));
        net = errno; close(socketFD);
    }
    errno = 0; execl("/usr/bin/true", "true", NULL); int execError = errno;
    errno = 0; pid_t pid = fork(); int forkError = errno;
    if (pid == 0) _exit(5);
    if (pid > 0) return 6;
    printf("{\"read\":%d,\"write\":%d,\"network\":%d,\"exec\":%d,\"fork\":%d}\n", rd, wr, net, execError, forkError);
    return (rd == EPERM && wr == EPERM && net == EPERM && execError == EPERM && forkError == EPERM) ? 0 : 7;
}
''')
    subprocess.run(["xcrun", "clang", str(source), "-o", str(helper)], check=True)
    result = subprocess.run(["/usr/bin/sandbox-exec", "-D", f"HELPER={helper}", "-p", profile,
                             str(helper), str(secret), str(output)], check=True, capture_output=True, text=True,
                            env={"LANG": "en_US.UTF-8"}, cwd="/", timeout=15)
    assert not output.exists()
    print("PASS: exact runner profile denied private file read, file write, loopback network, other exec and fork:", result.stdout.strip())
