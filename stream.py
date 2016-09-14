import tweepy
import json
import sys
import time
import logging
import logging.handlers
import html.parser
import gzip
import os
import logging
import logging.handlers

class GZipRotator:
    def __call__(self, source, dest):
        os.rename(source, dest)
        f_in = open(dest, 'rb')
        f_out = gzip.open("%s.gz" % dest, 'wb')
        f_out.writelines(f_in)
        f_out.close()
        f_in.close()
        os.remove(dest)

logformatter = logging.Formatter('%(asctime)s %(message)s',datefmt="%Y%m%d %H:%M:%S")
log = logging.handlers.TimedRotatingFileHandler('stream7.log', 'midnight', 1)
log.setLevel(logging.INFO)
log.setFormatter(logformatter)
#log.rotator = GZipRotator()

glog = logging.getLogger()
glog.addHandler(log)    
glog.setLevel(logging.DEBUG)

# define a Handler which writes INFO messages or higher to the sys.stderr
#console = logging.StreamHandler()
#console.setLevel(logging.INFO)
#cformatter = logging.Formatter('%(message)s')
#console.setFormatter(cformatter)
#clog = logging.getLogger()
#clog.addHandler(console)    
#clog.setLevel(logging.DEBUG)

# to prevent tweepy?
# urllib3_logger = logging.getLogger('urllib3')
# urllib3_logger.setLevel(logging.CRITICAL)
# warnings.filterwarnings("ignore") ??

glog.info( "Init." )
#clog.info("console init")
    
#override tweepy.StreamListener to add logic to on_status


class MyStreamListener(tweepy.StreamListener):
    def on_data(self, data):
        json_data = json.loads(data)
        try:
            txt = html.parser.HTMLParser().unescape(json_data['text'])
            scn = json_data['user']['screen_name']
        except KeyError:
            return True
        try:
            if json_data['retweeted_status']:
                #print("RT", txt )
                #print( "-" * 20 )
                return True #retweets not in log
        except:
            pass
        # C-j should be removed...
        txt1 = " ".join( txt.split() )
        print( scn, txt1 )
        glog.info( scn+" "+txt1 )
        #print(json.dumps(json_data, indent=4))
        print( "-" * 20 )
        return True
    def on_status(self, status):
        print(status.text)
    def on_error(self, status_code):
        if status_code == 420:
            print( "420" )
            #returning False in on_data disconnects the stream
            return False
    def on_limit(self, track):
        print(track + "\n")
        return

    def on_timeout(self):
        print("Timeout, sleeping for 60 seconds...\n")
        time.sleep(60)
        return 

if __name__ == '__main__':
    #listener = StdOutListener()
    #auth = tweepy.OAuthHandler(consumer_key, consumer_secret)
    #auth.set_access_token(access_token, access_token_secret)
    #stream = Stream(auth, listener)
    #stream.filter(follow=[38744894], track=['#pythoncentral'])
    #tweepy.debug(True) 

    consumer_key = ""
    consumer_secret = ""
    access_token = "177202620-"
    access_token_secret = ""

    my_StreamListener = MyStreamListener()

    # Replace the API_KEY and API_SECRET with your application's key and secret
    #https://apps.twitter.com/app/4442243/keys
    '''
    API_KEY="QMQfUOSEwcfpCQEXlikCbg"
    API_SECRET="fta25GOPBXpENey7iw2fpGFJjBaJ9gMEq4UqBRNubO8"
    auth = tweepy.AppAuthHandler(API_KEY, API_SECRET)
    '''
    auth = tweepy.OAuthHandler(consumer_key, consumer_secret)
    auth.set_access_token(access_token, access_token_secret)
    '''
    api = tweepy.API(auth, wait_on_rate_limit=True,
                     wait_on_rate_limit_notify=True)
    '''
    api = tweepy.API(auth, retry_count=3, retry_delay=5, wait_on_rate_limit=True, wait_on_rate_limit_notify=True, retry_errors=set([401, 404, 500, 503]))

    if (not api):
        print ("Can't Authenticate")
        sys.exit(-1)

    #auth = tweepy.OAuthHandler(consumer_key, consumer_secret)
    #auth.set_access_token(access_token, access_token_secret)
    #api = tweepy.API(auth)

    try:
        myStream = tweepy.Stream(auth = api.auth, listener=my_StreamListener)
        myStream.filter(track=["eller", "har", "var", "inte", "det", "den", "och", "är", "vi"], languages=["sv"])
    except tweepy.TweepError as e:
        print( e )
        myStream.disconnect()

