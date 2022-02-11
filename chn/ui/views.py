from datetime import datetime, timedelta

import logging

from pygal.style import *
import pygal
from flask import (
        Blueprint, render_template, request, url_for,
        redirect, g)
from flask_security import logout_user as logout
import unicodedata
from sqlalchemy import desc, func

from chn.ui.utils import get_flag_ip, get_country_ip, get_sensor_name
from chn.api.models import (
        Sensor, DeployScript as Script)
from chn.auth import login_required, current_user
from chn.auth.models import User, PasswdReset, ApiKey
from chn import db, chn
from chn.common.utils import (
        paginate_options, alchemy_pages, mongo_pages)
from chn.common.clio import Clio

ui = Blueprint('ui', __name__, url_prefix='/ui')
from chn import chn as app


PYGAL_CONFIG = pygal.config.Config()
PYGAL_CONFIG.js = (
    'https://kozea.github.io/pygal.js/javascripts/svg.jquery.js',
    'https://kozea.github.io/pygal.js/javascripts/pygal-tooltips.js',
)


def remove_control_characters(s):
    return "".join(ch for ch in s if unicodedata.category(ch)[0]!="C")


@app.template_filter()
def number_format(value):
    return '{:,d}'.format(value)


@ui.before_request
def check_page():
    """
    Cleans up any query parameter that is used
    to build pagination.
    """
    try:
        page = int(request.args.get('page', 1))
    except ValueError:
        page = 1
    g.page = page


@ui.route('/login/', methods=['GET'])
def login_user():
    if current_user.is_authenticated():
        return redirect(url_for('ui.dashboard'))
    return render_template('security/login_user.html')


@chn.route('/')
@ui.route('/dashboard/', methods=['GET'])
@login_required
def dashboard():
    clio = Clio()
    # Number of attacks in the last 24 hours.
    attackcount = clio.session.count(hours_ago=24)
    # TOP 5 attacker ips.
    top_attackers = clio.session.top_attackers(top=5, hours_ago=24)
    # TOP 5 attacked ports
    top_ports = clio.session.top_targeted_ports(top=5, hours_ago=24)
    # Top 5 honey pots with counts
    top_hp = clio.session.top_hp(top=5, hours_ago=24)
    # Top Honeypot sensors
    top_sensor = clio.session.top_sensor(top=5, hours_ago=24)
    # TOP 5 sigs
    freq_sigs = clio.hpfeed.top_sigs(top=5, hours_ago=24)
    return render_template('ui/dashboard.html',
                           attackcount=attackcount,
                           top_attackers=top_attackers,
                           top_ports=top_ports,
                           top_hp=top_hp,
                           top_sensor=top_sensor,
                           freq_sigs=freq_sigs,
                           get_sensor_name=get_sensor_name,
                           get_flag_ip=get_flag_ip,
                           get_country_ip=get_country_ip)


@ui.route('/attacks/', methods=['GET'])
@login_required
def get_attacks():
    clio = Clio()
    options = paginate_options(limit=10)
    options['order_by'] = '-timestamp'
    total = clio.session.count(**request.args.to_dict())
    sessions = clio.session.get(
            options=options, **request.args.to_dict())
    sessions = mongo_pages(sessions, total, limit=10)
    return render_template('ui/attacks.html', attacks=sessions,
                           sensors=Sensor.query, view='ui.get_attacks',
                           get_flag_ip=get_flag_ip, get_country_ip=get_country_ip,
                           get_sensor_name=get_sensor_name,
                           map_sessionid_to_hpfeedid=map_sessionid_to_hpfeedid,
                           **request.args.to_dict())


@ui.route('/feeds/', methods=['GET'])
@login_required
def get_feeds():
    clio = Clio()
    options = paginate_options(limit=10)
    options['order_by'] = '-_id'
    count, columns, feeds = clio.hpfeed.get_payloads(options, request.args.to_dict())
    channel_list = clio.hpfeed.channel_map.keys()
    feeds = mongo_pages(feeds, count, limit=10)
    return render_template('ui/feeds.html', feeds=feeds, columns=columns,
                           channel_list=channel_list, view='ui.get_feeds',
                           **request.args.to_dict())


@ui.route('/sensors/', methods=['GET'])
@login_required
def get_sensors():
    sensors = Sensor.query.all()
    total = Sensor.query.count()
    # Paginating the list.
    pag = paginate_options(limit=10)
    sensors = sensors[pag['skip']:pag['skip'] + pag['limit']]
    # Using mongo_pages because it expects paginated iterables.
    sensors = mongo_pages(sensors, total, limit=10)
    return render_template('ui/sensors.html', sensors=sensors,
                           view='ui.get_sensors', pag=pag)


@ui.route('/add-sensor/', methods=['GET'])
@login_required
def add_sensor():
    return render_template('ui/add-sensor.html')


@ui.route('/manage-deploy/', methods=['GET'])
@login_required
def deploy_mgmt():
    script_id = request.args.get('script_id')
    arch_id = request.args.get('arch_id')
    arch = ""
    if arch_id == "1":
        arch = "-arm"
    if not script_id or script_id == '0':
        script = Script(name='', notes='', script='')
    else:
        script = Script.query.get(script_id)
    return render_template(
            'ui/script.html', scripts=Script.query.order_by(Script.date.desc()),
            script=script, arch=arch)


@ui.route('/honeymap/', methods=['GET'])
@login_required
def honeymap():
    return render_template('ui/honeymap.html')


@ui.route('/add-user/', methods=['GET'])
@login_required
def settings():
    return render_template(
        'ui/settings.html', 
        users=User.query.filter_by(active=True),
        apikey=ApiKey.query.filter_by(user_id=current_user.id).first()
    )


@ui.route('/forgot-password/<hashstr>/', methods=['GET'])
def forgot_passwd(hashstr):
    logout()
    user = PasswdReset.query.filter_by(hashstr=hashstr).first().user
    return render_template('ui/reset-password.html', reset_user=user,
                           hashstr=hashstr)


@ui.route('/reset-password/', methods=['GET'])
def reset_passwd():
    return render_template('ui/reset-request.html')


def map_sessionid_to_hpfeedid(sessionid):
    clio = Clio()
    session_info = clio.session.get(_id=sessionid)
    session_info = session_info.__dict__
    hpfeed_id = session_info.get('hpfeed_id')
    return hpfeed_id


@ui.route('/attack/', methods=['GET'])
@login_required
def get_attack():
    clio = Clio()
    options = paginate_options(limit=10)
    options['order_by'] = '-_id'
    attack_info = clio.hpfeed.get_payloads(options, request.args.to_dict())[2]
    attack_info = next(attack_info)
    columns = attack_info.keys()
    # manually set since there's only one result
    count = 1
    attack_info = mongo_pages(attack_info, count, limit=10)
    return render_template('ui/attack-info.html', attack_info=attack_info, columns=columns,
                           view='ui.get_attack',
                           **request.args.to_dict())


def get_credentials_payloads(clio):
    credentials_payloads = []
    credentials_payloads += clio.hpfeed.get_payloads({'limit': 10000}, {"channel": "kippo.sessions"})[2]
    credentials_payloads += clio.hpfeed.get_payloads({'limit': 10000}, {"channel": "cowrie.sessions"})[2]
    return credentials_payloads


@app.route('/image/top_passwords.svg')
@login_required
def graph_passwords():
    clio = Clio()
    
    bar_chart = pygal.Bar(style=LightColorizedStyle, show_x_labels=True, config=PYGAL_CONFIG)
    bar_chart.title = "Kippo/Cowrie Top Passwords"
    clio = Clio()
    top_passwords = clio.hpfeed.count_passwords(get_credentials_payloads(clio))
    for password_data in top_passwords:
        password,count = password_data
        password = remove_control_characters(password)
        bar_chart.add(password, [{'label': password, 'xlink': '', 'value':count}])

    return bar_chart.render_response()


@app.route('/image/top_users.svg')
@login_required
def graph_users():
    clio = Clio()
    
    bar_chart = pygal.Bar(style=LightColorizedStyle, show_x_labels=True, config=PYGAL_CONFIG)
    bar_chart.title = "Kippo/Cowrie Top Users"
    clio = Clio()
    top_users = clio.hpfeed.count_users(get_credentials_payloads(clio))
    for user_list in top_users:
        user,password = user_list
        user = remove_control_characters(user)
        bar_chart.add(user, [{'label':user, 'xlink':'', 'value':password}])

    return bar_chart.render_response()


@app.route('/image/top_combos.svg')
@login_required
def graph_combos():
    clio = Clio()
    
    bar_chart = pygal.Bar(style=LightColorizedStyle, show_x_labels=True, config=PYGAL_CONFIG)
    bar_chart.title = "Kippo/Cowrie Top User/Passwords"
    clio = Clio()
    top_combos = clio.hpfeed.count_combos(get_credentials_payloads(clio))
    for combo_list in top_combos:
        user,password = combo_list
        user = remove_control_characters(user)
        bar_chart.add(user,[{'label':user,'xlink': '', 'value':password}])

    return bar_chart.render_response()


def top_kippo_cowrie_attackers(clio):
    top_attackers = []
    top_attackers += clio.session._tops('source_ip', 10, honeypot='kippo')
    top_attackers += clio.session._tops('source_ip', 10, honeypot='cowrie')

    import collections
    grouped = collections.Counter()
    for attacker in top_attackers:
        grouped[attacker['source_ip']] += int(attacker['count'])
    return [{'source_ip': ip, 'count': count} for ip, count in sorted(grouped.items(),
                                                                      key=lambda x: x[1], reverse=True)]

@app.route('/image/top_sessions.svg')
@login_required
def graph_top_attackers():
    clio = Clio()
    
    bar_chart = pygal.Bar(style=LightColorizedStyle, show_x_labels=True, config=PYGAL_CONFIG)
    bar_chart.title = "Kippo/Cowrie Top Attackers"
    clio = Clio()
    top_attackers = top_kippo_cowrie_attackers(clio)
    print(top_attackers)
    for attacker in top_attackers:
        bar_chart.add(str(attacker['source_ip']), attacker['count'])

    return bar_chart.render_response()


@ui.route('/chart')
def chart():
    return render_template('ui/chart.html')
