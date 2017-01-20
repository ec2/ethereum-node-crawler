import sys
import csv
import pymysql


host = '127.0.0.1'
user = 'simon'
password = ''
db = 'main'


def connect_database():
    try:
        connection = pymysql.connect(host, user, password, db)
        try:
            with connection.cursor() as cursor:
                cursor.execute('SELECT VERSION()')
                result = cursor.fetchone()
            # Check if anything at all is returned
            if not result:
                print('seems connected, but there is nothing in it')
            else:
                print('connected. fetched following %s' % result)
        finally:
            return connection
    except pymysql.Error:
        print('could not connect to the database')
    return None


def clear_all(connection):
    with connection.cursor() as cursor:
        sql = "DROP TABLE IF EXISTS RoutingTable, Pubkeys;"
        cursor.execute(sql)
        connection.commit()
    print('All tables dropped!')


def create_pubkeys(connection):
    with connection.cursor() as cursor:
        # create a new table if not already exists
        sql = "CREATE TABLE IF NOT EXISTS Pubkeys (" \
              "pubkey VARCHAR(128) NOT NULL," \
              "status BOOL DEFAULT 0," \
              "PRIMARY KEY (pubkey)" \
              ")"
        cursor.execute(sql)
        connection.commit()
    print('Pubkeys table created!')


def add_pubkey(connection, pubkey, status):
    with connection.cursor() as cursor:
        sql = "INSERT INTO Pubkeys (pubkey, status)" \
              "VALUES (%s, %s)" \
              "ON DUPLICATE KEY UPDATE status=%s"
        cursor.execute(sql, (pubkey, status, status))
        connection.commit()
#    print('new pubkey added!')


def create_routingtable(connection):
    with connection.cursor() as cursor:
        # create a new table if not already exists
        # time TIMESTAMP(6)
        sql = "CREATE TABLE IF NOT EXISTS  RoutingTable (" \
              "pubkey VARCHAR(128) NOT NULL," \
              "ip VARCHAR(39) NOT NULL," \
              "tcp_port INT2 unsigned NOT NULL," \
              "udp_port INT2 unsigned NOT NULL," \
              "reputation TINYINT DEFAULT 0," \
              "rlpx_version TINYINT DEFAULT 0," \
              "time VARCHAR(255) NULL," \
              "count INT unsigned DEFAULT 1," \
              "FOREIGN KEY (pubkey) REFERENCES Pubkeys(pubkey)" \
              "ON DELETE CASCADE ON UPDATE CASCADE," \
              "PRIMARY KEY (pubkey, ip, tcp_port, udp_port)" \
              ")"
        cursor.execute(sql)
        connection.commit()
    print('RoutingTable table created!')


def add_node(connection, node):
    with connection.cursor() as cursor:
        sql = "INSERT INTO RoutingTable (pubkey, ip, tcp_port, udp_port, reputation, rlpx_version)" \
              "VALUES (%s, %s, %s, %s, %s, %s)" \
              "ON DUPLICATE KEY UPDATE reputation=%s, rlpx_version=%s, count=count+1" 
        cursor.execute(sql, (node[0], node[1], node[2], node[3], node[4], node[5], node[4], node[5]))
        connection.commit()


def load_from_csv(connection, filename):
    with open(filename, "r") as file_obj:
        csvfile = csv.reader(file_obj, delimiter=',')
        for row in csvfile:
            if len(row) != 6:
                continue
            add_pubkey(connection, row[0], 0)
            add_node(connection, row)
    print("{} loaded".format(filename))


def main():
    if len(sys.argv) < 2:
        print("need filename")
        sys.exit(1)

    filenames = sys.argv[1:]

    print("begin initializing tables")

    # connect to db
    connection = connect_database()
    if not connection:
        print('database connection failed!')
        exit(1)

    # clear all existing tables
    clear_all(connection)

    create_pubkeys(connection)
    create_routingtable(connection)

    for filename in filenames:
        load_from_csv(connection, filename)
    
    # close connection
    connection.close()


if __name__ == "__main__":
    main()
