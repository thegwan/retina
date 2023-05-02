import subprocess, re, os
import toml
import argparse


# allowed % packet drop
EPSILON=0.00001
def execute(cmd, executable):
    stop = 0
    popen = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, universal_newlines=True)
    for stdout_line in iter(popen.stdout.readline, ''):
        print(stdout_line, end='')
        if 'SW Dropped' in stdout_line:
            num = re.findall('\d*\.*\d+\%', stdout_line)
            if not num: continue
            value = float(num[0].split('%')[0]) 
            if value > EPSILON :
                print(f'TERMINATING, current SW drops {value} greater than {EPSILON}...')
                stream = os.popen(f'pidof {executable}')
                pid = stream.read()
                os.system(f'sudo kill -INT {pid}')
                stop = 0      # continue decreasing buckets
        elif 'DROPPED' in stdout_line:
            num = re.findall('\d*\.*\d+\%', stdout_line)
            if not num: continue
            value = float(num[0].split('%')[0]) 
            if value == 0:
                # 0 drops
                print('Zero drops...')
                stop = 1
            elif value <= EPSILON :
                print(f'Epsilon {value}% dropped...')
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

    executable = f'/home/gerryw/retina/target/release/{binary}'
    cmd = f'sudo env LD_LIBRARY_PATH=$LD_LIBRARY_PATH RUST_LOG=error {executable} -c {config_file} -o {outfile}'

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

        stop_code = execute(cmd, executable)
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
