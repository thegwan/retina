import subprocess, re, os
import toml
import argparse

def modify_binary(template_file, old_text, new_text):
    with open(template_file, 'r', encoding='utf-8') as file:
        filedata = file.read()
    if old_text in filedata:
        print(f'replacing `{old_text}` with `{new_text}`')
        filedata = filedata.replace(old_text, new_text)
        with open('/home/gerryw/retina/examples/extract_features/src/main.rs', 'w', encoding='utf-8') as file:
            file.write(filedata)
        return True
    return False

def compile_binary(release=True):
    status = True
    if release:
        cmd = f'cargo build --release --bin extract_features --features timing'
    else:
        cmd = f'cargo build --bin extract_features --features timing'
    popen = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    for stderr_line in iter(popen.stderr.readline, ''):
        # print(stderr_line, end='')
        if 'Compiling' in stderr_line or 'Finished' in stderr_line:
            print(f'\t> {stderr_line}', end='')
        if 'error' in stderr_line:
            print(f'\t> {stderr_line}', end='')
            status = False
    popen.stdout.close()
    popen.stderr.close()
    popen.wait()
    return status

def run_binary(feature, offline=True):
    status = True
    binary = 'extract_features'
    executable = f'/home/gerryw/retina/target/release/{binary}'
    if offline:
        config_file = '/home/gerryw/retina/scripts/base_offline_config.toml'
    else:
        config_file = '/home/gerryw/retina/scripts/base_online_config.toml'
    out_file = f'/mnt/netml/results/test/out_features_{feature}.json'
    cmd = f'sudo env LD_LIBRARY_PATH=$LD_LIBRARY_PATH RUST_LOG=error {executable} -c {config_file} -o {out_file}'

    EPSILON = 0.0001

    popen = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, universal_newlines=True)
    for stdout_line in iter(popen.stdout.readline, ''):
        print(stdout_line, end='')
        if 'SW Dropped' in stdout_line:
            num = re.findall('\d*\.*\d+\%', stdout_line)
            if not num: continue
            value = float(num[0].split('%')[0]) 
            if value > EPSILON :
                print(f'TERMINATING, current SW drops {value} greater than {EPSILON}...')
                stream = os.popen(f'pidof {binary}')
                pid = stream.read()
                os.system(f'sudo kill -INT {pid}')
                status = False     # Failed, skip
    popen.stdout.close()
    popen.wait()
    return status

def profile_memory(feature):
    out_file = f'/mnt/netml/results/test/mem_features_{feature}.txt'
    # cmd = f'top -d 1 -b | grep --line-buffered extract_feature'
    cmd = f'top -d 1 -b | grep --line-buffered extract_feature > {out_file}'

    print(f'Starting memory profiler, writing to {out_file}')
    popen = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, universal_newlines=True)
    # for stdout_line in iter(popen.stdout.readline, ''):
    #     print(stdout_line, end='')
    return popen

def main(args):
    ft_names = [
        'du',
        'proto',
        # 's_bytes_sum',
        # 'd_bytes_sum',
        # 's_ttl_mean',
        # 'd_ttl_mean',
        # 's_load',
        # 'd_load',
        # 's_bytes_mean',
        # 'd_bytes_mean',
        # 's_pkt_cnt',
        # 'd_pkt_cnt',
        # 's_iat_mean',
        # 'd_iat_mean',
        # 'tcp_rtt',
        # 'syn_ack',
        # 'ack_dat',
    ]

    for feature in ft_names:
        
        # print(feature)
        # old_text = 'use retina_core::subscription::features::Features;'
        # new_text = f'use retina_core::subscription::features_{feature}::Features;'
        # if not modify_binary('/home/gerryw/retina/scripts/base_extract_features.rs', old_text, new_text):
        #     print(f'Failed to modify template for `{feature}`, skipping...')
        # if not compile_binary(release=True):
        #     print(f'Failed to compile for `{feature}`, skipping...')
        #     continue
        mem_profiler = profile_memory(feature)
        print("here")
        if not run_binary(feature, offline=False):
            print(f'Failed to run {feature}, skipping...')
            continue
        mem_profiler.terminate()
        # terminate won't kill the child top process since it is running with shell=True
        os.system(f'pkill -f top')
            
            

    # binary = args.binary

    # duration = int(args.duration)
    # start = int(args.start)
    
    # config_file = args.config
    # outfile = args.outfile

    # executable = f'/home/gerryw/retina/target/release/{binary}'
    # cmd = f'sudo env LD_LIBRARY_PATH=$LD_LIBRARY_PATH RUST_LOG=error {executable} -c {config_file} -o {outfile}'

    # config=toml.load(config_file)
    # n_cores = len(config['online']['ports'][0]['cores'])
    # print(config)
    # for b in range(start, 0, -n_cores):
    #     print(f'Running {binary} with {b} buckets')
        
    #     config['online']['monitor']['log'] = None
    #     config['online']['duration'] = duration
    #     config['online']['ports'][0]['sink']["nb_buckets"] = b

    #     f = open(config_file, 'w')
    #     toml.dump(config, f)
    #     f.close()

    #     stop_code = execute(cmd, executable)
    #     if stop_code > 0:
    #         print(f'Stop code {stop_code}: done')
    #         break

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-b', '--binary')
    parser.add_argument('-d', '--duration')
    parser.add_argument('-s', '--start')
    parser.add_argument('-c', '--config')
    parser.add_argument('-o', '--outfile')
    return parser.parse_args()

if __name__ == '__main__':
    main(parse_args())