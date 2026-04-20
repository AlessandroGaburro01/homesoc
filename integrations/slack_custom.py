# Copyright (C) 2015, Wazuh Inc. — modificato per HomeSOC
# Script: /var/ossec/integrations/slack.py
# Versione: HomeSOC 1.0 — messaggi contestuali per UC-01/03/04/06

import json
import os
import sys

ERR_NO_REQUEST_MODULE = 1
ERR_BAD_ARGUMENTS = 2
ERR_FILE_NOT_FOUND = 6
ERR_INVALID_JSON = 7

try:
    import requests
except Exception:
    print("No module 'requests' found. Install: pip install requests")
    sys.exit(ERR_NO_REQUEST_MODULE)

debug_enabled = False
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
json_alert = {}
json_options = {}
LOG_FILE = f'{pwd}/logs/integrations.log'
ALERT_INDEX = 1
WEBHOOK_INDEX = 3


def main(args):
    global debug_enabled
    try:
        bad_arguments: bool = False
        if len(args) >= 4:
            msg = '{0} {1} {2} {3} {4}'.format(
                args[1], args[2], args[3],
                args[4] if len(args) > 4 else '',
                args[5] if len(args) > 5 else ''
            )
            debug_enabled = len(args) > 4 and args[4] == 'debug'
        else:
            msg = '# ERROR: Wrong arguments'
            bad_arguments = True

        with open(LOG_FILE, 'a') as f:
            f.write(msg + '\n')

        if bad_arguments:
            debug('# ERROR: Exiting, bad arguments. Inputted: %s' % args)
            sys.exit(ERR_BAD_ARGUMENTS)

        process_args(args)

    except Exception as e:
        debug(str(e))
        raise


def process_args(args) -> None:
    debug('# Running HomeSOC Slack script')
    alert_file_location: str = args[ALERT_INDEX]
    webhook: str = args[WEBHOOK_INDEX]
    options_file_location: str = ''

    for idx in range(4, len(args)):
        if args[idx][-7:] == 'options':
            options_file_location = args[idx]
            break

    json_options = get_json_options(options_file_location)
    json_alert = get_json_alert(alert_file_location)

    debug('# Generating message')
    msg: any = generate_msg(json_alert, json_options)

    if not len(msg):
        debug('# ERROR: Empty message')
        raise Exception

    debug(f'# Sending message {msg} to Slack server')
    send_msg(msg, webhook)


def debug(msg: str) -> None:
    if debug_enabled:
        print(msg)
        with open(LOG_FILE, 'a') as f:
            f.write(msg + '\n')


# ── helpers ───────────────────────────────────────────────────────────────────

def _ts(alert):
    """Timestamp leggibile dal campo ISO dell'alert."""
    raw = alert.get('timestamp', '')
    if len(raw) >= 19:
        return raw[:10] + ' ' + raw[11:19]
    return raw

def _agent(alert):
    return alert.get('agent', {}).get('name', 'N/A')

def _fields(*pairs):
    """Costruisce la lista fields per Slack: [('Label', 'valore'), ...]"""
    return [{'title': k, 'value': v, 'short': True} for k, v in pairs if v]


# ── messaggi per use case ─────────────────────────────────────────────────────

def _msg_uc01(alert, data):
    """UC-01 — SSH Brute Force (rule 100001)"""
    src_ip = (data.get('srcip')
              or data.get('src_ip')
              or alert.get('full_log', '').split('srcip=')[-1].split()[0]
              or 'IP sconosciuto')
    return {
        'color': 'danger',
        'pretext': ':red_circle: *SSH Brute Force rilevato — UC-01*',
        'title': 'Tentativi ripetuti di accesso SSH falliti',
        'text': f'IP sorgente `{src_ip}` ha superato la soglia di tentativi SSH falliti su *{_agent(alert)}*.',
        'fields': _fields(
            ('IP sorgente', f'`{src_ip}`'),
            ('Agent', _agent(alert)),
            ('Rule', '100001 · Level 10'),
            ('Timestamp', _ts(alert)),
        ),
        'footer': 'HomeSOC · MITRE T1110.001',
        'ts': alert.get('id', ''),
    }


def _msg_uc03(alert, data, rule_id):
    """UC-03 — FIM macOS (rule 100020 / 100023)"""
    fim_file = (data.get('fim.file')
                or data.get('fim_file')
                or '')
    fim_event = (data.get('fim.event')
                 or data.get('fim_event')
                 or '')

    # fallback: estrai il path dalla description della rule
    if not fim_file:
        desc = alert.get('rule', {}).get('description', '')
        if ': ' in desc:
            fim_file = desc.split(': ')[-1]

    event_label = {
        'modified_or_deleted': 'Modificato / Eliminato',
        'modified_or_new':     'Modificato / Nuovo',
        'new':                 'Nuovo file',
        'deleted':             'Eliminato',
    }.get(fim_event, fim_event or 'Modifica rilevata')

    level = alert['rule']['level']
    return {
        'color': 'danger' if level >= 12 else 'warning',
        'pretext': ':large_orange_circle: *Modifica file critico — UC-03 FIM*',
        'title': 'File system integrity: file modificato su macOS',
        'text': f'Il file `{fim_file}` è stato modificato sul MacBook Pro M1.',
        'fields': _fields(
            ('File', f'`{fim_file}`'),
            ('Evento', event_label),
            ('Agent', _agent(alert)),
            ('Rule', f'{rule_id} · Level {level}'),
            ('Timestamp', _ts(alert)),
        ),
        'footer': 'HomeSOC · MITRE T1565.001',
        'ts': alert.get('id', ''),
    }


def _msg_uc04(alert, data, rule_id):
    """UC-04 — NAS Port Monitor (rule 100030 / 100031)"""
    host  = data.get('nas.host')  or data.get('nas_host')  or 'N/A'
    port  = data.get('nas.port')  or data.get('nas_port')  or 'N/A'
    proto = data.get('nas.proto') or data.get('nas_proto') or 'tcp'

    # fallback full_log parsing
    if host == 'N/A':
        for part in alert.get('full_log', '').split():
            if part.startswith('host='):
                host = part.split('=', 1)[1]
            elif part.startswith('port='):
                port = part.split('=', 1)[1]

    level = alert['rule']['level']
    return {
        'color': 'danger',
        'pretext': ':red_circle: *Porta inattesa sul NAS — UC-04*',
        'title': 'NAS: porta non prevista rilevata',
        'text': f'Il NAS `{host}` espone la porta `{port}/{proto}` che non è nella lista attesa.',
        'fields': _fields(
            ('Host NAS', host),
            ('Porta', f'`{port}/{proto}`'),
            ('Agent', _agent(alert)),
            ('Rule', f'{rule_id} · Level {level}'),
            ('Timestamp', _ts(alert)),
        ),
        'footer': 'HomeSOC · MITRE T1078',
        'ts': alert.get('id', ''),
    }


def _msg_uc06(alert, data, rule_id):
    """UC-06 — Rogue Device (rule 100040 / 100041)"""
    mac = (data.get('rogue.mac') or data.get('rogue_mac')
           or data.get('mac')    or '')
    ip  = (data.get('rogue.ip')  or data.get('rogue_ip')
           or data.get('ip')     or '')

    # fallback: estrai da full_log  MAC=xx:xx IP=xx.xx
    if not mac:
        for part in alert.get('full_log', '').split():
            if part.upper().startswith('MAC='):
                mac = part.split('=', 1)[1]
            elif part.upper().startswith('IP='):
                ip  = part.split('=', 1)[1]

    # fallback: estrai da rule description
    if not mac:
        desc = alert.get('rule', {}).get('description', '')
        for token in desc.split():
            if ':' in token and len(token) == 17:
                mac = token
            elif '.' in token and token.replace('.','').isdigit():
                ip = token

    level = alert['rule']['level']
    return {
        'color': 'warning',
        'pretext': ':large_yellow_circle: *Dispositivo sconosciuto in rete — UC-06*',
        'title': 'Rogue device: MAC non in whitelist',
        'text': f'Rilevato dispositivo non autorizzato sulla LAN.',
        'fields': _fields(
            ('MAC address', f'`{mac}`' if mac else 'N/A'),
            ('IP assegnato', f'`{ip}`'  if ip  else 'N/A'),
            ('Rule', f'{rule_id} · Level {level}'),
            ('Timestamp', _ts(alert)),
        ),
        'footer': 'HomeSOC · MITRE T1200',
        'ts': alert.get('id', ''),
    }


def _msg_generic(alert, data):
    """Fallback per rule non mappate (stile originale Wazuh)"""
    level = alert['rule']['level']
    color = 'good' if level <= 4 else ('warning' if level <= 7 else 'danger')
    return {
        'color': color,
        'pretext': 'WAZUH Alert',
        'title': alert['rule'].get('description', 'N/A'),
        'text': alert.get('full_log', ''),
        'fields': _fields(
            ('Agent', '({0}) - {1}'.format(
                alert.get('agent', {}).get('id', '000'),
                _agent(alert))),
            ('Location', alert.get('location', '')),
            ('Rule ID', '{0} _(Level {1})_'.format(alert['rule']['id'], level)),
        ),
        'ts': alert.get('id', ''),
    }


# ── entry point ───────────────────────────────────────────────────────────────

def generate_msg(alert: any, options: any) -> any:
    rule_id = str(alert['rule']['id'])
    data    = alert.get('data', {})

    if rule_id == '100001':
        msg = _msg_uc01(alert, data)
    elif rule_id in ('100020', '100023'):
        msg = _msg_uc03(alert, data, rule_id)
    elif rule_id in ('100030', '100031'):
        msg = _msg_uc04(alert, data, rule_id)
    elif rule_id in ('100040', '100041'):
        msg = _msg_uc06(alert, data, rule_id)
    else:
        msg = _msg_generic(alert, data)

    if options:
        msg.update(options)

    return json.dumps({'attachments': [msg]})


def send_msg(msg: str, url: str) -> None:
    headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8'}
    res = requests.post(url, data=msg, headers=headers, timeout=10)
    debug('# Response received: %s' % res.json)


def get_json_alert(file_location: str) -> any:
    try:
        with open(file_location) as alert_file:
            return json.load(alert_file)
    except FileNotFoundError:
        debug("# JSON file for alert %s doesn't exist" % file_location)
        sys.exit(ERR_FILE_NOT_FOUND)
    except json.decoder.JSONDecodeError as e:
        debug('Failed getting JSON alert. Error: %s' % e)
        sys.exit(ERR_INVALID_JSON)


def get_json_options(file_location: str) -> any:
    try:
        with open(file_location) as options_file:
            return json.load(options_file)
    except FileNotFoundError:
        debug("# JSON file for options %s doesn't exist" % file_location)
    except BaseException as e:
        debug('Failed getting JSON options. Error: %s' % e)
        sys.exit(ERR_INVALID_JSON)


if __name__ == '__main__':
    main(sys.argv)
