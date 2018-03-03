#! /usr/bin/env python3
# -*- coding:utf-8 -*-

import sqlite3
import os
import sys
import getopt


def usage():
    print('''
    add/delete a new user or change password.
    USAGE:
    -h, --help      display this help and exit
    -a, --add       add a new user
    -p, --password  set password
    -d, --delete    delete a user
    ''')


def check_validation(options):
    def in_option(opt):
        for name, value in options:
            if name in opt:
                return True
        return False

    if in_option(('-d', '--delete')) and len(options) == 1:
        return

    if in_option(('-d', '--delete')) and in_option(('-a', '--add')):
        print('-a should not use with -d')
        sys.exit()
    if not (in_option(('-a', '--add')) and in_option(('-p', '--password'))):
        print('-a should use with -p')
        sys.exit()


if __name__ == '__main__':
    try:
        options, args = getopt.getopt(sys.argv[1:], 'ha:d:p:', ['help', 'add=', 'delete=', 'password'])
    except getopt.GetoptError:
        sys.exit()

    check_validation(options)

    for name, value in options:
        if name in ('-h', '--help'):
            usage()
            sys.exit()

    script_path = os.path.realpath(__file__)
    script_dir = os.path.dirname(script_path)
    os.chdir(script_dir)

    USERNAME = ''
    PASSWORD = ''

    if not os.path.exists('./ACCOUNT.sqlite'):
        print('Create database ACCOUNT.')
    conn = sqlite3.connect('ACCOUNT.sqlite')
    cursor = conn.cursor()
    try:
        cursor.execute(
            'CREATE TABLE USER (NAME VARCHAR(20) NOT NULL,PASSWORD VARCHAR(20) NOT NULL,PRIMARY KEY (NAME))')
        conn.commit()
        print('Initialize Table USER.')
    except sqlite3.OperationalError:
        pass

    for name, value in options:
        if name in ('-d', '--delete'):
            cursor.execute('DELETE FROM USER WHERE NAME=:name', {'name': value})
            conn.commit()
            cursor.close()
            conn.close()
        if name in ('-a', '--add'):
            USERNAME = value
        if name in ('-p', '--password'):
            PASSWORD = value

    if len(USERNAME) and len(PASSWORD):
        try:
            cursor.execute('INSERT INTO USER VALUES(?,?)', (USERNAME, PASSWORD))
        except sqlite3.IntegrityError:
            print('User {} has exist'.format(USERNAME))
        finally:
            conn.commit()
            cursor.close()
            conn.close()
