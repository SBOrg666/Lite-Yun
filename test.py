import psutil

for proc in psutil.process_iter():
    try:
        pinfo = proc.as_dict(attrs=['pid', 'name', 'username', 'exe', 'cpu_percent', 'memory_percent'])
    except psutil.NoSuchProcess:
        pass
    else:
        print(pinfo)