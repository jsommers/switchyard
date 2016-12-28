import re

def humanize_bandwidth(bits):
    '''
    Accept some number of bits/sec (i.e., a link capacity) as an
    integer, and return a string representing a 'human'(-like)
    representation of the capacity, e.g., 10 Mb/s, 1.5 Mb/s,
    900 Gb/s.

    As is the standard in networking, capacity values are assumed
    to be base-10 values (not base 2), so 1000 is 1 Kb/s.
    '''
    unit = ''
    divisor = 1
    if bits < 1000:
        unit = 'bits'
        divisor = 1
    elif bits < 1000000:
        unit = 'Kb'
        divisor = 1000
    elif bits < 1000000000:
        unit = 'Mb'
        divisor = 1000000
    elif bits < 1000000000000:
        unit = 'Gb'
        divisor = 1000000000
    elif bits < 1000000000000000:
        unit = 'Tb'
        divisor = 1000000000000
    else:
        raise Exception("Can't humanize that many bits.")

    if bits % divisor == 0:
        value = int(bits/divisor)
    else:
        value = bits/divisor

    return "{} {}/s".format(value, unit)

def unhumanize_bandwidth(bitsstr):
    '''
    Take a string representing a link capacity, e.g., 10 Mb/s, and
    return an integer representing the number of bits/sec.
    Recognizes:
        - 'bits/sec' or 'b/s' are treated as plain bits per second
        - 'Kb' or 'kb' as thousand bits/sec
        - 'Mb' or 'mb' as million bits/sec
        - 'Gb' or 'gb' as billion bits/sec
        - 'Tb' or 'tb' as trillion bits/sec
        - if second character is 'B', quantity is interpreted as bytes/sec
        - any subsequent characters after the first two are ignored, so
          Kb/s Kb/sec Kbps are interpreted identically.

    Returns None if the string doesn't contain anything parseable.
    '''
    if isinstance(bitsstr, int):
        return bitsstr

    mobj = re.match('^\s*([\d\.]+)\s*(.*)\s*$', bitsstr)
    if not mobj:
        return None
    value, units = mobj.groups()
    value = float(value)
    multipliers = { 'b':1, 'k':1e3, 'm':1e6, 'g':1e9, 't':1e12 }
    if not units:
        units = 'bits'
    mult = multipliers.get(units[0].lower(), 0)
    bits = 1
    if len(units) > 1:
        if units[1] == 'B': bits = 8
    # print (bitsstr, value, mult, bits)
    return int(value * mult * bits)

# a couple aliases
humanize_capacity = humanize_bandwidth
unhumanize_capacity = unhumanize_bandwidth

def humanize_delay(delay):
    '''
    Accept a floating point number presenting link propagation delay
    in seconds (e.g., 0.1 for 100 milliseconds delay), and return
    a human(-like) string like '100 milliseconds'.  Handles values as 
    small as 1 microsecond, but no smaller.

    Because of imprecision in floating point numbers, a relatively easy
    way to handle this is to convert to string, then slice out sections.
    '''
    delaystr = '{:1.06f}'.format(delay) 
    decimal = delaystr.find('.') 
    seconds = int(delaystr[:decimal])
    millis = int(delaystr[-6:-3])
    micros = int(delaystr[-3:])
    # print (delay,delaystr,seconds,millis,micros)
    units = ''
    microsecs = micros + 1e3 * millis + 1e6 * seconds
    if micros > 0:
        units = ' \u00B5sec'
        value = int(microsecs)
    elif millis > 0:
        units = ' msec'
        value = int(microsecs / 1000)
    elif seconds > 0:
        units = ' sec'
        value = int(microsecs / 1000000)
    else:
        units = ' sec'
        value = delay
    if value > 1:
        units += 's'
    return '{}{}'.format(value, units)

def unhumanize_delay(delaystr):
    '''
    Accept a string representing link propagation delay (e.g., 
    '100 milliseconds' or '100 msec' or 100 millisec') and return
    a floating point number representing the delay in seconds.
    Recognizes:
        - us, usec, micros* all as microseconds
        - ms, msec, millisec* all as milliseconds
        - s, sec* as seconds

    returns None on parse failure.
    '''
    if isinstance(delaystr, float):
        return delaystr

    mobj = re.match('^\s*([\d\.]+)\s*(\w*)', delaystr)
    if not mobj:
        return None
    value, units = mobj.groups()
    value = float(value)
    if not units:
        divisor = 1.0
    elif units == 'us' or units == 'usec' or units.startswith('micros'):
        divisor = 1e6
    elif units == 'ms' or units == 'msec' or units.startswith('millis'):
        divisor = 1e3
    elif units == 's' or units.startswith('sec'):
        divisor = 1.0
    else:
        return None
    return value / divisor
