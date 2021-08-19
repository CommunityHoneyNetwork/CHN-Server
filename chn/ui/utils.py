import requests
from flask import current_app as app, url_for
from chn.ui import constants
from config import CHN_SERVER_HOME
import os
from werkzeug.contrib.cache import SimpleCache
from ipaddress import ip_address
import struct
from chn.api.models import Sensor

flag_cache = SimpleCache(threshold=1000, default_timeout=300)
country_cache = SimpleCache(threshold=1000, default_timeout=300)
sensor_cache = SimpleCache(threshold=1000, default_timeout=300)


def is_private_addr(ip):
    # 10.0.0.0/8
    # 127.0.0.0/8
    # 172.16.0.0/12
    # 192.168.0.0/16
    # fc00::/7 (unique local addresses)
    # ::1/128 (localhost)

    try:
        ip_obj = ip_address(ip)
        # Make exception for ::ffff/96 (ipv4-mapped)
        if ip_obj.version == 6 and ip_obj.ipv4_mapped:
            return False
        if ip_obj.is_private:
            return True
    except Exception as e:
        print('Error (%s) on is_private_addr: %s' % (e, ip))

    return False


def get_flag_ip(ipaddr):
    if is_private_addr(ipaddr):
        return url_for('static', filename=constants.DEFAULT_FLAG_URL)

    flag = flag_cache.get(ipaddr)
    if not flag:
        flag = _get_flag_ip(ipaddr)
        flag_cache.set(ipaddr, flag)
    return flag


def get_country_ip(ipaddr):
    if is_private_addr(ipaddr):
        return constants.DEFAULT_COUNTRY_NAME

    name = country_cache.get(ipaddr)
    if not name:
        name = _get_country_ip(ipaddr)
        country_cache.set(ipaddr, name)
    return name


def get_sensor_name(sensor_id):
    sensor_name = sensor_cache.get(sensor_id)
    if not sensor_name:
        for s in Sensor.query:
            if s.uuid == sensor_id:
                sensor_name = s.hostname
                sensor_cache.set(sensor_id, sensor_name)
                break
    print('Name: %s' % sensor_name)
    return sensor_name


def _get_flag_ip(ipaddr):
    """
    Returns an address where the flag is located.
    Defaults to static immge: '/static/img/unknown.png'
    """
    flag_path = url_for(
        'static', filename='img/flags-iso/shiny/64') + '/{}.png'
    geo_api = 'https://freegeoip.app/json/{}'
    try:
        # Using threatstream's geospray API to get
        # the country code for this IP address.
        r = requests.get(geo_api.format(ipaddr))
        ccode = r.json()['country_code']
        app.logger.debug('Found CC code: {}'.format(ccode))
    except Exception:
        app.logger.warning(
            "Could not determine flag for ip: {}".format(ipaddr))
        return url_for('static', filename=constants.DEFAULT_FLAG_URL)
    else:
        # Constructs the flag source using country code
        flag = flag_path.format(ccode.upper())
        local_flag_path = '/static/img/flags-iso/shiny/64/{}.png'.format(
            ccode.upper())

        if os.path.exists(CHN_SERVER_HOME + "/chn"+local_flag_path):
            return flag
        else:
            return url_for('static', filename=constants.DEFAULT_FLAG_URL)


def _get_country_ip(ipaddr):
    geo_api = 'https://freegeoip.app/json/{}'
    try:
        # Using threatstream's geospray API to get
        # the country name for this IP address.
        r = requests.get(geo_api.format(ipaddr))
        name = r.json()['country_code']
        return name
    except Exception:
        app.logger.warning("Could not determine country name for ip: {}".format(ipaddr))
        return constants.DEFAULT_COUNTRY_NAME
