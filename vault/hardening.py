"""
JARAYON XOTIRASINI HIMOYALASH (Linux)

Vault ochilgach, KEK va DK jarayon RAM'ida turadi - bu muqarrar. Lekin
ularni o'qishning eng oson yo'llarini yopish mumkin:

  - RLIMIT_CORE = 0: jarayon qulasa, core dump faylga kalitlar yozilmaydi.
  - PR_SET_DUMPABLE = 0: shu foydalanuvchining BOSHQA jarayonlari ptrace /
    gdb / process_vm_readv orqali xotirani o'qiy olmaydi, /proc/<pid>/mem va
    /proc/<pid>/environ ham faqat root uchun ochiq bo'ladi.

Bu root'ga qarshi himoya EMAS (root baribir hamma narsani ko'ra oladi) -
lekin chegara xizmati/boshqa oddiy servis buzilganda Vault xotirasiga
yetib borishni qiyinlashtiradi.
"""
import ctypes
import sys

PR_SET_DUMPABLE = 4


def harden_process() -> dict[str, bool]:
    result = {"core_dump_disabled": False, "ptrace_blocked": False}

    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        result["core_dump_disabled"] = True
    except Exception as exc:  # Windows yoki cheklangan muhit
        print(f"[HARDENING][OGOHLANTIRISH] core dump o'chirilmadi: {exc}", file=sys.stderr)

    if sys.platform.startswith("linux"):
        try:
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            if libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) == 0:
                result["ptrace_blocked"] = True
            else:
                print("[HARDENING][OGOHLANTIRISH] prctl(PR_SET_DUMPABLE) muvaffaqiyatsiz", file=sys.stderr)
        except Exception as exc:
            print(f"[HARDENING][OGOHLANTIRISH] prctl chaqirib bo'lmadi: {exc}", file=sys.stderr)
    else:
        print("[HARDENING][OGOHLANTIRISH] Linux emas - xotira himoyasi ishlamaydi.", file=sys.stderr)

    return result
