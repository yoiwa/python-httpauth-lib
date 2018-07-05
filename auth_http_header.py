import collections
import re

tokens = {
    'quoted_string': r'\"(?:[\t !#-\[\]-~\u0080-\U0010FFFF]|\\[\t !-~\u0080-\U0010FFFF])*\"',
    'token': r"[!#$%&\'*+\-.^_\`|~0-9A-Za-z]+",
    'token68': r"[A-Za-z0-9-._~+/]*=*(?=[ \t\r\n]*(?:$|,))",
    # token68 MUST be followed by WS and [EOS or comma].
    # token "=" will not be followed by comma by syntax.
    'OWS': r'[ \t\r\n]*',
    'comma': r',',
}
tokens['key_equals_value'] = \
    '(?P<key>{0}){2}={2}(?P<value>(?:{0}|{1}))'.format(
        tokens['token'], tokens['quoted_string'], tokens['OWS'])

tokens['commas_key_equals_value'] = \
    '{1}(?:,{1})*{0}'.format(
        tokens['key_equals_value'], tokens['OWS'])

ext_value_regexp = re.compile(
    r"^(?P<charset>[A-Za-z0-9!#$%&+\-^_\`{}~]+)" +
    r"\'(?P<language>[A-Za-z0-9\-]*)\'" +
    r"(?P<value>(?:\%[0-9A-Fa-f][0-9A-Fa-f]|[---0-9A-Za-z!#$&+.^_\`|~]+)*)$"
    )
b_percent_regexp = re.compile(b'%([0-9A-FA-f][0-9A-Fa-f])')

def _tokenset(l, skip_ws=True):
    r = '|'.join('(?P<{}>{})'.format(k,tokens[k]) for k in l)
    if skip_ws:
        r = tokens['OWS'] + r
    return re.compile(r)

tokensets = {
    'token':            _tokenset(['token']),
    'token68':          _tokenset(['token68']),
    'commas_auth_param': _tokenset(['commas_key_equals_value']),
    'auth_param_first':  _tokenset(['token68', 'key_equals_value']),
    'comma':            _tokenset(['comma'])
}

def process_rfc5987(k, v):
    assert(k[-1] == '*')
    m = ext_value_regexp.match(v)
    if m == None:
        raise ValueError("bad rfc5987-style header: {}".format(k))
    charset = m.group('charset').lower()
    pvalue = m.group('value').encode('ascii')
    if charset not in ('iso-8859-1', 'utf-8'):
        raise ValueError("bad charset in rfc-5987-style header: {}".format(k))
    dvalue = b_percent_regexp.sub(lambda mo: bytes.fromhex(mo.group(1).decode('ascii')), pvalue)
    try:
        dvalue = dvalue.decode(charset)
    except ValueError:
        raise ValueError("unencodable character in value: {}, {}".format(k, pvalue.decode('ascii')))
    k = k[0:-1]
    return k, dvalue

def parse_http7615_header(s):
    s = s.strip(" \t\r\n")
    p = 0
    slen = len(s)

    def eos():
        return p == slen

    def eat_token(d, ts):
        nonlocal s, p
        r = eat_token_maybe(d, ts)
        if r == None:
            raise ValueError("parse error cannot take tokenset {} in input position {}".format(ts, p))
        return r

    def eat_token_maybe(d, ts):
        nonlocal s, p
#        print("@@@ {}: s={!r}###{!r}, p={}, ts={}, re={!r}".format(d, s[0:p], s[p:], p, ts, tokensets[ts]))
        m = tokensets[ts].match(s, p)
        if m == None:
            return None
        p = m.end()
        token = m.lastgroup
        value = m.group(token)
        return token, value, m

    def eat_commas(d):
        if eat_token_maybe(d, 'comma'):
            while eat_token_maybe(d, 'comma'):
                pass
            return True
        return False

    def parse_challenge():
        auth_scheme = eat_token('challenge_top', 'token')[1].capitalize()
        params = {}
        eat_commas('challenge_before_1')
        r = eat_token_maybe('challenge_1', 'auth_param_first')
        if r:
            (t, v, m) = r
            if t == 'token68':
                return (auth_scheme, {"": v})
            else:
                key = m.group('key').lower()
                value = parse_http_str(m.group('value'))
                if key[-1] == '*':
                    key, value = process_rfc5987(key, value)
                params.append((key, value))
        while True:
            r = eat_token_maybe('challenge_2+', 'commas_auth_param')
            if not r:
                break
            (t, v, m) = r
            key = m.group('key').lower()
            value = parse_http_str(m.group('value'))
            if key[-1] == '*':
                key, value = process_rfc5987(key, value)
            if key in params:
                raise ValueError("in auth scheme {}, key {} appeared twice at position {}".format(auth_scheme, key, pos))
            params[key] = value
        return (auth_scheme, params)

    def parse_http_str(s):
        if s[0] == '"':
            return re.sub(r"\\(.)", r'\1', s[1:-1])
        else:
            return s

    schemes = []
    eat_commas('before_first_challenge')
    while True:
        schemes.append(parse_challenge())
        if eos():
            break
        if not eat_commas('after_challenge'):
            raise ValueError('error at pos {}'.format(p))
        if eos():
            break
    return schemes

header_rules = {
    'digest': {
        'stale': 3,
        'algorithm': 3,
        'realm': 2,
        'domain': 2,
        'nonce': 2,
        'opaque': 2,
        'qop': 2,
    },
    '*': {
        'realm': 2
    }
}

token_fullregexp = re.compile("^" + tokens['token'] + "$")
ascii_fullregexp = re.compile("^[ -~]*$")
unsafe_byte_regexp = re.compile(b'[^---0-9A-Za-z!#$&+.^_\`|~]')

def encode_param_val(s, k, v):
    mode = header_rules.get(s.lower(), header_rules['*'])
    mode = mode.get(k.lower(), 0)
    is_numeric = isinstance(v, int)

    v_token = v = str(v)

    is_token_safe = token_fullregexp.match(v)
    is_ascii_safe = ascii_fullregexp.match(v)

    v_str = '"' + re.sub(r'([\\\"])', r'\\\1', v) + '"'

    if mode == 0:
        # prefer str
        if (is_token_safe and is_numeric):
            return k, v_token
        elif is_ascii_safe:
            return k, v_str
    elif mode == 1:
        # prefer token
        if is_token_safe:
            return k, v_token
        elif is_ascii_safe:
            return k, v_str
    elif mode == 2:
        # forbid RFC5987
        return k, v_str
    elif mode == 3:
        # prefer token, forbit RFC5987
        if is_token_safe:
            return k, v_token
        else:
            return k, v_str

    # fallthrough: here we have non-ascii character
    v_bytes = v.encode('utf-8')
    q_bytes = unsafe_byte_regexp.sub((lambda mo: b"%%%02x" % mo.group(0)[0]),
                                     v_bytes)
    return k + "*", "utf-8''" + q_bytes.decode('ascii')

def encode_http7615_header(chal):
    out = []
    for m, pl in chal:
        if "" in pl.keys():
            out.append("{} {}".format(m, pl['']))
        else:
            po = []
            for k, v in pl.items():
                po.append("{}={}".format(*encode_param_val(m, k, v)))
            out.append("{} {}".format(m, ", ".join(po)))
    return ", ".join(out)

def encode_http7615_authinfo(pl):
    po = []
    for k, v in pl.items():
        po.append("{}={}".format(*encode_param_val('digest', k, v))) # TODO
    return ", ".join(po)

if __name__=='__main__':
#    print(repr(parse_http7615_header(r'Digest foo=bar, roo="var abc\"k\a", Basic agnofo1_/= , Mutual foo=bar, roo="vari", Mutual foo=2, var="xx"')))
#    print(repr(parse_http7615_header(r', Digest foo=bar, , roo="var abc\"k\a", , Basic agnofo1_/=  , , mutual , Foo=bar, ,, roo="vari", , Mutual foo=2, , var="xx", , , ')))
#    print(repr(parse_http7615_header(r', Digest foo=bar, , roo="var abc\"k\a", , Basic agnofo1_/=  , , mutual , Foo=bar, ,, roo*=iso-8859-1' + "''" + '%a1%2cb%2c%22d%22, , Mutual foo=2, , var="xx", , , ')))
#    print(repr(parse_http7615_header(r', Digest foo=bar, , roo="var abc\"k\a", , Basic agnofo1_/=  , , mutual , Foo=bar, ,, roo*=utf-8' + "'en'" + '%c2%a1%2cb%2c%22d%22, , Mutual foo=2, , var="xx", , , ')))
    print(encode_http7615_header(
        [('Digest', {'roo': 'var abc"ka', 'foo': 'bar'}),
         ('Basic', {'': 'agnofo1_/='}),
         ('Mutual', {'roo': '¡,b,"d"', 'foo': 'bar'}),
         ('Mutual', {'var': 'xx', 'foo': '2'})]))
    print(encode_http7615_header(
        [('Digest', {'stale': '1', 'algorithm': '1', 'realm': '1', 'username': '1'}),
         ('Digest', {'stale': '日本語', 'algorithm': '日本語', 'realm': '日本語', 'username': '日本語'}),
         ('Mutual', {'roo': '¡,b,"d"', 'foo': 'bar'}),
         ('Mutual', {'stale': '日本語', 'algorithm': '日本語', 'realm': '日本語', 'username': '日本語'}),
         ('Mutual', {'var': 'xx', 'foo': '2'})]))
