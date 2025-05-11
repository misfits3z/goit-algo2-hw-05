import mmh3
import math
import time
import json


class HyperLogLog:
    def __init__(self, p=5):
        self.p = p
        self.m = 1 << p
        self.registers = [0] * self.m
        self.alpha = self._get_alpha()
        self.small_range_correction = 5 * self.m / 2  

    def _get_alpha(self):
        if self.p <= 16:
            return 0.673
        elif self.p == 32:
            return 0.697
        else:
            return 0.7213 / (1 + 1.079 / self.m)

    def add(self, item):
        x = mmh3.hash(str(item), signed=False)
        j = x & (self.m - 1)
        w = x >> self.p
        self.registers[j] = max(self.registers[j], self._rho(w))

    def _rho(self, w):
        return len(bin(w)) - 2 if w > 0 else 32

    def count(self):
        Z = sum(2.0**-r for r in self.registers)
        E = self.alpha * self.m * self.m / Z

        if E <= self.small_range_correction:
            V = self.registers.count(0)
            if V > 0:
                return self.m * math.log(self.m / V)

        return E


def get_data_from_json(filepath):
    get_data = []
    with open(filepath, "r") as f:
        for line in f:
            try:
                data = json.loads(line.strip())
                IP_address = data.get("remote_addr", "")
                if IP_address.count(".") == 3:
                    get_data.append(IP_address)
            except json.JSONDecodeError:
                print("Error")
    return get_data


# метод set для підрахунку унікальних IP-адрес
def count_exact_unique_ips(IPs):
    return len(set(IPs))


def count_approx_unique_ips(IPs):
    hll = HyperLogLog(p=14)
    print("p=14, теоретична похибка ±0.8%, приблизне споживання пам'яті ~16 KB")
    for IP in IPs:
        hll.add(IP)
    return hll.count()


# час виконання функції
def measure_execution_time(func, *args):
    start = time.time()
    result = func(*args)
    end = time.time()
    return result, end - start


def main():
    log_file = "lms-stage-access.log"

    # Отримуємо дані з файлу
    IPs = get_data_from_json(log_file)

    # Вимірюємо час
    set_result, set_time = measure_execution_time(count_exact_unique_ips, IPs)
    approx_result, approx_time = measure_execution_time(count_approx_unique_ips, IPs)

    print("\nРезультати порівняння:")

    print("---------------------------------------------------------------")
    print(f"{'':<25}{'|':<3}{'Метод set':<15}{'|':<3}{'HyperLogLog':<20}")
    print("---------------------------------------------------------------")
    print(
        f"{'Унікальні елементи':<25}{'|':<3}{set_result:<15}{'|':<3}{round(approx_result, 1):<20}"
    )
    print("---------------------------------------------------------------")
    print(
        f"{'Час виконання (сек.)':<25}{'|':<3}{round(set_time, 3):<15}{'|':<3}{round(approx_time, 3):<20}"
    )
    print("---------------------------------------------------------------")


if __name__ == "__main__":
    main()
