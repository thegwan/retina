import subprocess, sys, re, os
import toml
import time
import argparse


EPSILON=0
def execute(cmd):
    stop = 0
    popen = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, universal_newlines=True)
    for stdout_line in iter(popen.stdout.readline, ''):
        print(stdout_line, end='')
        if 'SW Dropped' in stdout_line:
            num = re.findall('\d*\.*\d+\%', stdout_line)
            print(num)
            if len(num) == 1 and float(num[0].split('%')[0]) > EPSILON :
                print(f'TERMINATING, SW drops greater than {EPSILON}...')
                stream = os.popen(f'pidof {cmd}')
                pid = stream.read()
                os.system('sudo kill -INT ' + pid)
                stop = 0      # continue decreasing buckets
        elif 'DROPPED' in stdout_line:
            num = re.findall('\d*\.*\d+\%', stdout_line)
            print(f'DROPPED: {num}')
            if len(num) == 1 and float(num[0].split('%')[0]) == 0:
                # 0 drops
                print('Zero drops...')
                stop = 1
            elif len(num) == 1 and float(num[0].split('%')[0]) <= EPSILON :
                print(f'Epsilon {EPSILON} drops...')
                stop = 2

    popen.stdout.close()
    popen.wait()
    return stop

def main(args):
    binary = args.binary

    duration = int(args.duration)
    start = int(args.start)
    
    config_file = args.config
    outfile = args.outfile

    cmd = f'sudo env LD_LIBRARY_PATH=$LD_LIBRARY_PATH RUST_LOG=error /home/gerryw/retina/target/release/{binary} -c {config_file} -o {outfile}'

    config=toml.load(config_file)
    n_cores = len(config['online']['ports'][0]['cores'])
    print(config)
    for b in range(start, 0, -n_cores):
        print(f'Running {binary} with {b} buckets')
        
        config['online']['monitor']['log'] = None
        config['online']['duration'] = duration
        config['online']['ports'][0]['sink']["nb_buckets"] = b

        f = open(config_file, 'w')
        toml.dump(config, f)
        f.close()

        stop_code = execute(cmd)
        if stop_code > 0:
            print(f'Stop code {stop_code}: done')
            break

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