#######################################
#                                     #
#            Astrea Fuzzer            #
#       Created because I needed      #
#    to fuzz some stuff but didn't    #
#        want to do it manually       #
#                                     #
#######################################

import sys
import os
import argparse
import re

#Remote fuzzing
def fuzz_remote():
    return

#Local fuzzing
def fuzz_local():
    if args.input == 'stdin':
        for i in range(args.start, args.end, args.increment):
            if not args.quiet:
                print("[+]Fuzzing application binary " + str(i) + " characters")
            if os.system("python -c 'print \"A\"*" + str(i) + "\' | " + args.file + " >/dev/null"):
                print("Segfault with input length " + str(i))
                sys.exit(0)
    else:
        for i in range(args.start, args.end, args.increment):
            if not args.quiet:
                print("[+]Fuzzing binary with " + str(i) + " characters")
            if os.system("python -c \'print \"A\"*" + str(i) + "\' | xargs " + args.file + " >/dev/null"):
                print("Segfault with input length " + str(i))
                sys.exit(0)


#Custom argparser types
def vector_checker(vector):
    if vector == 'local' or vector == 'remote':
        return vector
    raise argparse.ArgumentTypeError('Argument must be "local" or "remote"')

def ip_checker(ip):
    if re.match(r'^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$', ip):
        return ip
    raise argparse.ArgumentTypeError('Argument must be a valid IP address')

def input_checker(arg):
    if arg == 'stdin' or arg == 'args':
        return arg
    raise argparse.ArgumentTypeError('Argument must be "stdin" or "args"')

if __name__ == "__main__":

    parser = argparse.ArgumentParser(prog='Astrea',
                                     usage='%(prog)s [options]',
                                     description="Astrea is used to fuzz local or remote binary executables.",
                                     add_help=False)


    #Mandatory Arguments
    parser.add_argument('-v', '--vector',
                        type=vector_checker,   #Comment out for Python 2
                        action='store',
                        required=True,
                        help='Vector of fuzzing', 
                        metavar='[local|remote] example: local')
    parser.add_argument('-s', '--start',
                        type=int,
                        action='store',
                        required=True,
                        help="Starting value of fuzzing string length",
                        metavar='[int] example: 1000')
    parser.add_argument('-e', '--end',
                        type=int,
                        action='store',
                        required=True,
                        help="Ending value of fuzzing string length",
                        metavar='[int] example: 5000')
    parser.add_argument('-i', '--increment',
                        type=int,
                        action='store',
                        required='True',
                        help="Value for fuzzing string length to be incremented by",
                        metavar='[int] example: 100')

    #Remote Arguments
    parser.add_argument('--ip',
                        type=ip_checker,    
                        action='store',
                        help='REMOTE ONLY: target ip for fuzzing',
                        metavar='[ip] example: 10.10.14.134')
    parser.add_argument('--port',
                        type=int,
                        action='store',
                        help='REMOTE ONLY: target port for fuzzing',
                        metavar='[port] example: 8081')

    #Local Arguments
    parser.add_argument('--file',
                        type=ascii,    #Comment out for Python 2
                        action='store',
                        help='LOCAL ONLY: target executable file',
                        metavar='[file] example: /bin/vulnerable')
    parser.add_argument('--input',
                        type=input_checker,
                        action='store',
                        help='LOCAL ONLY: method of passing input - via stdin or arguments',
                        metavar='[stdin|args] example: stdin')
    
    #Optional Arguments
    parser.add_argument('-q', '--quiet',
                        action='store_true',
                        help='Disables verbose')

    #Help Arguments
    parser.add_argument('-h', '--help',
                        action='help')
    
    args = parser.parse_args()
    
    if args.vector == 'local':
        if not args.quiet:
            print('[+] Fuzzing locally')
        fuzz_local()

    if args.vector == 'remote':
        if not args.quiet:
            print('[+] Fuzzing remotely')
        fuzz_remote()
