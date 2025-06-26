# datarecord.py
import subprocess
import os
import time

BUFFER_HEADERS = "timestamp,syscall,direction,pid,ppid,uid,auid,comm,exe\n"


def ensure_buffers():
    os.makedirs("dataset", exist_ok=True)
    for fname in ["buffer1.csv", "buffer2.csv"]:
        fpath = os.path.join("dataset", fname)
        if not os.path.exists(fpath):
            with open(fpath, "w") as f:
                f.write(BUFFER_HEADERS)


def create_buffer(buffer_name):
    path = os.path.join("dataset", buffer_name)
    with open(path, "w") as f:
        f.write(BUFFER_HEADERS)
    return path


def delete_buffer(buffer_name):
    path = os.path.join("dataset", buffer_name)
    if os.path.exists(path):
        os.remove(path)


def collect_system_calls(duration_sec=60, which_buffer="buffer1.csv"):
    output_path = os.path.join("dataset", which_buffer)
    print(f"[🛠️] Recording syscalls for {duration_sec}s to {output_path}")

    # Ensure buffer file exists with header before appending
    if not os.path.exists(output_path):
        create_buffer(which_buffer)

    sysdig_command = [
        "sudo", "sysdig",
        "evt.type in (execve,execveat,clone,fork,vfork,ptrace,setuid,setgid,setresuid,setresgid,capset,capget,setgroups,"
        "unlink,unlinkat,rename,renameat,chmod,fchmod,chown,fchown,symlink,symlinkat,link,linkat,"
        "socket,connect,accept,bind,reboot,init_module,delete_module,"
        "mount,umount2,pivot_root,kexec_load,perf_event_open,mmap2)",
        "-p", "%evt.time,%evt.type,%evt.dir,%proc.pid,%proc.ppid,%user.uid,%user.loginuid,%proc.name,%proc.exepath"
    ]

    with open(output_path, "a") as f:
        proc = subprocess.Popen(sysdig_command, stdout=f)
        time.sleep(duration_sec)
        proc.terminate()

    print(f"[✅] Done recording to {output_path}")
    return output_path

