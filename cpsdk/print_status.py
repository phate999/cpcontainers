import cs
import time
import datetime

while True:
    timestamp = datetime.datetime.now().strftime('%m/%d/%y %H:%M:%S')
    system_id = cs.CSClient().get('config/system/system_id')
    cpu = cs.CSClient().get('status/system/cpu')
    memory = cs.CSClient().get('status/system/memory')
    print(f'{timestamp} Hostname: {system_id}')
    print(f'CPU Status: {cpu}')
    print(f'Memory Status: {memory}\n')
    time.sleep(3600)
