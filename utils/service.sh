#!/bin/sh
set -e

# TODO Load Virtual Machines into tmpfs, if enabled.

_about_upstart() {
    echo "Using Upstart technique.."
}

_install_configuration() {
    cat > /etc/default/cuckoo << EOF
# Configuration file for the Cuckoo Sandbox service.

# Username to run Cuckoo under, by default cuckoo.
# USERNAME="cuckoo"

# Directory for Cuckoo, defaults to the "cuckoo" directory in the
# home directory of the cuckoo user.
# CUCKOODIR="/home/cuckoo/cuckoo/"

# Log directory, defaults to the log/ directory in the Cuckoo setup.
# LOGDIR="/home/cuckoo/cuckoo/log/"

# IP address that the Cuckoo API will bind on.
# IPADDR="localhost"
EOF
}

_remove_configuration() {
    rm -f /etc/default/cuckoo
}

_install_upstart() {
    cat > /etc/init/cuckoo.conf << EOF
# Cuckoo daemon service.

description "cuckoo daemon"
start on runlevel [2345]
chdir /home/cuckoo/cuckoo
pre-start script
    exec vmcloak-vboxnet0
    exec vmcloak-iptables
end script
exec ./cuckoo.py -u cuckoo -d
EOF

    cat > /etc/init/cuckoo-api.conf << EOF
# Cuckoo API server service.

env CONFFILE="/etc/default/cuckoo"
env IPADDR="127.0.0.1"

pre-start script
    [ -f "\$CONFFILE" ] && . "\$CONFFILE"
end-script

description "cuckoo api server"
start on started cuckoo
stop on stopped cuckoo
setuid cuckoo
chdir /home/cuckoo/cuckoo
exec ./utils/api.py -H "\$IPADDR" 2>> log/api.log
EOF

    cat > /etc/init/cuckoo-process.conf << EOF
# Cuckoo results processing service.

description "cuckoo results processing"
start on started cuckoo
stop on stopped cuckoo
setuid cuckoo
chdir /home/cuckoo/cuckoo
exec ./utils/process.py auto 2>> log/process.log
EOF

    cat > /etc/init/cuckoo-distributed.conf << EOF
# Cuckoo distributed API service.

env CONFFILE="/etc/default/cuckoo"
env IPADDR="127.0.0.1"

pre-start script
    [ -f "\$CONFFILE" ] && . "\$CONFFILE"
end-script

description "cuckoo distributed api service"
start on started cuckoo
stop on stopped cuckoo
setuid cuckoo
chdir /home/cuckoo/cuckoo
exec ./utils/dist.py "\$IPADDR" 2>> log/process.log
EOF
    echo "Cuckoo Service scripts installed!"
}

_remove_upstart() {
    rm -f /etc/init/cuckoo.conf
    rm -f /etc/init/cuckoo-api.conf
    rm -f /etc/init/cuckoo-process.conf
    rm -f /etc/init/cuckoo-distributed.conf
}

_reload_upstart() {
    initctl reload-configuration
}

_start_upstart() {
    initctl start cuckoo "IP=$1"
}

_stop_upstart() {
    initctl stop cuckoo
}

_restart_upstart() {
    initctl restart cuckoo "IP=$1"
}

_about_systemv() {
    echo "Using SystemV technique.."
}

_install_systemv() {
    cat > /etc/init.d/cuckoo << EOF
#!/bin/sh
# Cuckoo service.

PIDFILE="/var/run/cuckoo.pid"
CONFFILE="/etc/default/cuckoo"

# Default configuration values.
USERNAME="cuckoo"
CUCKOODIR="/home/cuckoo/cuckoo/"
LOGDIR="/home/cuckoo/cuckoo/log/"
IPADDR="localhost"

# Load configuration values.
[ -f "\$CONFFILE" ] && . "\$CONFFILE"

_start() {
    if [ -f "\$PIDFILE" ]; then
        echo "Cuckoo is already running.. please stop it first!"
        exit 1
    fi

    vmcloak-vboxnet0
    vmcloak-iptables

    echo -n "Starting Cuckoo daemon.. "
    nohup python "\$CUCKOODIR/cuckoo.py" -u "\$USERNAME" \
        -d 2>&1 > /dev/null &
    PID=\$! && echo "\$PID" && echo "\$PID" >> "\$PIDFILE"

    echo -n "Starting Cuckoo API server.. "
    nohup python "\$CUCKOODIR/utils/api.py" -u "\$USERNAME" \
        -H "\$IPADDR" 2>&1 >> "\$LOGDIR/api.log" &
    PID=\$! && echo "\$PID" && echo "\$PID" >> "\$PIDFILE"

    echo -n "Starting Cuckoo results processing.. "
    nohup python "\$CUCKOODIR/utils/process.py" -u "\$USERNAME" \
        auto -p 2 2>&1 >> "\$LOGDIR/process.log" &
    PID=\$! && echo "\$PID" && echo "\$PID" >> "\$PIDFILE"

    echo -n "Starting Cuckoo Distributed API.. "
    nohup python "\$CUCKOODIR/utils/dist.py" -u "\$USERNAME" \
        "\$IPADDR" 2>&1 >> "\$LOGDIR/dist.log" &
    PID=\$! && echo "\$PID" && echo "\$PID" >> "\$PIDFILE"

    echo "Cuckoo started.."
}

_stop() {
    if [ ! -f "\$PIDFILE" ]; then
        echo "Cuckoo isn't running.."
        exit 1
    fi

    echo "Stopping Cuckoo processes.."
    kill \$(cat "\$PIDFILE")
    echo "Cuckoo stopped.."
    rm -f "\$PIDFILE"
}

case "\$1" in
    start)
        _start \$2
        ;;

    stop)
        _stop
        ;;

    restart|force-reload)
        _stop
        _start \$2
        ;;

    *)
        echo "Usage: \$0 {start|stop|restart|force-reload}" >&2
        exit 1
        ;;
esac
EOF

    chmod +x /etc/init.d/cuckoo
    echo "Cuckoo Service script installed!"
}

_remove_systemv() {
    rm -f /etc/init.d/cuckoo
}

_reload_systemv() {
    : # Nothing to do here.
}

_start_systemv() {
    /etc/init.d/cuckoo start
}

_stop_systemv() {
    /etc/init.d/cuckoo stop
}

_restart_systemv() {
    /etc/init.d/cuckoo restart
}

case "$(lsb_release -is)" in
    Ubuntu)
        alias _about=_about_upstart
        alias _install=_install_upstart
        alias _remove=_remove_upstart
        alias _reload=_reload_upstart
        alias _start=_start_upstart
        alias _stop=_stop_upstart
        alias _restart=_restart_upstart
        ;;

    Debian)
        alias _about=_about_systemv
        alias _install=_install_systemv
        alias _remove=_remove_systemv
        alias _reload=_reload_systemv
        alias _start=_start_systemv
        alias _stop=_stop_systemv
        alias _restart=_restart_systemv
        ;;

    *)
        echo "Unsupported Linux distribution.."
        exit 1
esac

if [ "$#" -eq 0 ]; then
    echo "Usage: $0 <install|remove|start|stop>"
    exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "This script should be run as root."
    exit 1
fi

case "$1" in
    install)
        _about
        _install
        _install_configuration
        _reload
        ;;

    remove)
        _remove
        _remove_configuration
        _reload
        ;;

    start)
        _start "$2"
        ;;

    stop)
        _stop
        ;;

    restart)
        _restart "$2"
        ;;

    *)
        echo "Requested invalid action."
        exit 1
esac