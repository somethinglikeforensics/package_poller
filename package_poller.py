from datetime import datetime
import logging
logging.basicConfig(
    filename= "jsPackagePoller-{}.log".format(datetime.utcnow().strftime("%m%d-%H%M%S")),
    format='%(asctime)s %(levelname)-8s %(message)s',
    level=logging.INFO,
    datefmt='%Y-%m-%d %H:%M:%S')

from source_urls import urls
import hashlib

import re
import sqlite3

from pathlib import Path
import smtplib
from email.message import EmailMessage
import requests
from chepy import Chepy2

SMTP_SERVER = '<SMTP_SERVER_ADDRESS>'
ALERT_TO_EMAIL = '<REPORTING_EMAIL>'

class JsPollDb:    
    def __init__(self, import_list=urls):
        """ connects to db objects / path
            if import list is provided, adds to urls from list to db targets 
            takes target list for worker from db                       
            """                
        try:
            path = self.database_path()
            self.conn = sqlite3.connect(path)
            logging.info("JsPollDb.init: connected to database {}".format(path))

        except:
            logging.error("JsPollDb.init: could not connect to {}".format(path))
        
        # if import list has been specificed add items to Db
        if import_list:
            self.add_targets(import_list)            

        # returns list of dicts                
        for target in self.read_target_list():             
            results = self.__versions_worker(self.return_target_hash(target))   # returns result_dict

            if results["result"] == "new_version":
                match_locations = self.compare_versions(old_version_hash=results["results_list"][-1][0], new_version_hash=self.create_filestore_version(results))                
                report_text = self.snippet_reporter(match_locations, target) 
                self.email_snippet(report_text)
    
    
    def __versions_worker(self, target_dict):
        if target_dict["js_sha256"] == None:
            logging.error("Poll check not yet run on dict object")
        else:
            cur = self.conn.cursor()
            cur.execute("""
                    SELECT js_sha256
                    FROM targets
                    INNER JOIN versions
                    ON TARGETS.url_md5 = VERSIONS.url_md5
                    WHERE TARGETS.url_md5 = ?
                    ORDER BY version DESC""", (target_dict["url_md5"],)) 
            
            target_dict["results_list"] = cur.fetchall() # list of tuples           
                                    
            no_previous_versions = len(target_dict["results_list"])
            # if first version of file in table
            if no_previous_versions == 0: 
                logging.info("JsPollDb.check_versions: first sighting of {}. (version {}) Saving to Disk ".format(target_dict["url"],no_previous_versions+1))                                               
                cur.execute("INSERT into versions (first_seen, last_seen, js_sha256, js_char_size, url_md5, version) values (?,?,?,?,?,?)", (target_dict["poll_ts"],target_dict["poll_ts"],target_dict["js_sha256"], target_dict["js_size"], target_dict["url_md5"], no_previous_versions+1)) 
                self.conn.commit()
                self.create_filestore_version(target_dict)
                target_dict["result"] = "first_sighting"               
                
            else:                
                # previous version, update last seen timestamp                
                if target_dict["js_sha256"] == target_dict["results_list"][0][0]:                    
                    logging.info("JsPollDb.check_versions: no changes to latest version of {}.".format(target_dict["url"]))                    
                    cur.execute("UPDATE versions SET last_seen = ? WHERE url_md5 = ?", (target_dict["poll_ts"], target_dict["url_md5"]))
                    self.conn.commit()
                    target_dict["result"] = "known_version"

                # new version of file detected 
                elif target_dict["js_sha256"] not in target_dict["results_list"][0]:                                        
                    logging.info("JsPollDb.check_versions: *NEW FILE VERSION DETECTED* of {}.".format(target_dict["url"]))                    
                    self.conn.commit()
                    cur.execute("INSERT into versions (first_seen, last_seen, js_sha256, js_char_size, url_md5, version) values (?,?,?,?,?,?)", (target_dict["poll_ts"],target_dict["poll_ts"],target_dict["js_sha256"], target_dict["js_size"], target_dict["url_md5"], no_previous_versions+1)) 
                    self.create_filestore_version(target_dict)
                    target_dict["result"] = "new_version"

                if target_dict["js_sha256"] != target_dict["results_list"][0][0] and target_dict["js_sha256"] in target_dict["results_list"][0]:
                    # package has been rolled back to a previous versions
                    logging.info("JsPollDb.check_versions: rollback to previous version detected: {}.".format(target_dict["url"]))
                    target_dict["result"] = "reused_version"

        return target_dict          

    def create_filestore_version(self, target_dict):
        body = requests.get(target_dict["url"])
        path = self.filestore_path(target_dict["js_sha256"])
        with open (path, 'wb') as file:
            logging.info("JsPollDb.create_filestore_version: New version written to {}.".format(path))
            file.write(body.content)

        if path.is_file():
            return str(target_dict["js_sha256"])
        else:
            return False
    
    def compare_versions(self, old_version_hash, new_version_hash):
        """takes two hashes, grabs the related files and compares
            returns a dict of changes
         """ 
                       
        self.old_version_content=self.filestore_path(old_version_hash).read_text() 
        self.new_version_content=self.filestore_path(new_version_hash).read_text()
        
        chef = Chepy(self.old_version_content, self.new_version_content)
        diff = chef.diff(state=1)
        
        result_regex = re.compile(r'([^{]+->[^}]+)|({+\+[^}]+)|({\-[^}]+)')       
        
        matches_list = result_regex.finditer(str(diff))
        
        matches_locs = list()
        for match in matches_list:                       
            loc = match.span()
            matches_locs.append(loc)                       
        
        return matches_locs
        
    def email_snippet(self, snippet):
        msg = EmailMessage()        
        msg['Subject'] = 'Monitored Js Package has been modified'
        msg['From'] = 'package_poller@dev.com'
        msg['To'] = ALERT_TO_EMAIL
        msg.set_content(snippet)
        
        try:
            with smtplib.SMTP(SMTP_SERVER, 25) as smtp:
                smtp.send_message(msg)
                return True
        
        except:
            return False
        
    
    def snippet_reporter(self, matches_locs_list, target):              

        summary_text = (
                        f'\nThis is an email from the SOC iHUBs Javascript Package Monitor which polls javascript libraries used by TalkTalks public facing websites.\n'
                        f'{round((len(matches_locs_list)+1)/2)} changes were detected in the content of a package hosted at {target["url"]}\n'
                        f'This packages is serving TalkTalk Website: XXX URL.\n\n'
                        f'The list below provides snippets of the original and changed text and should be reviewed for malicious indicators\n'
                        f'Copies of the full files are retained on the SOC iHub and can be provided for additional analysis.\n\n\n')          
                              
        
        counter = 1  
        for match in matches_locs_list:                        
            snippet_start = match[0] - 25
            snippet_end = match[1] + 25                               
            
            snippet_text = (
                f'# Change {counter} of {round((len(matches_locs_list)+1)/2)}\n' 
                f'# OLD VERSION (CHARS {snippet_start}-{snippet_end}):    {self.old_version_content[snippet_start:snippet_end]}\n' 
                f'# NEW VERSION (CHARS {snippet_start}-{snippet_end}):    {self.new_version_content[snippet_start:snippet_end]}\n\n')

            summary_text+=snippet_text
            counter+=1

        return summary_text        
                        
    def add_targets(self, target_list):
        cur = self.conn.cursor()        
        for url in target_list:                
                url_md5 = hashlib.md5(url.encode('utf-8')).hexdigest()
                
                cur.execute("""\
                            INSERT OR IGNORE into targets (url, url_md5, added_ts) values (?,?,?)
                            """, (url, url_md5, self.ts_now()))                
        self.conn.commit()
        result = self.conn.total_changes
        if result>0:
            logging.info("JsPollDb.add_targets: {} new targets added to database.".format(result)) 

    def read_target_list(self):
        """ returns list of target urls hashes from the db             
            """
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM targets;")                        
        return self.target_dict_list(cur.fetchall())

    def target_dict_list(self, target_list):
        list_of_dicts = list()        
        for target in target_list:
            poll_dict = dict()
            poll_dict["url"] = target[1]
            poll_dict["url_md5"] = target[2]
            poll_dict["added_ts"] = target[3]            
            # following are placeholder, values added to dict after hashlookup
            poll_dict["poll_ts"] = None
            poll_dict["js_sha256"] = None
            poll_dict["js_size"] = None
            poll_dict["results_list"] = list() 
            list_of_dicts.append(poll_dict)
        return list_of_dicts

    def return_target_hash(self, target_dict):
        """ gets content of remote url and calucates hash 
            compares hashes to known previous hashes
            saves new versions to raw\sha256 file names
            returns true false for matches
            """
        try:
            body = requests.get(target_dict["url"])
            target_dict["js_sha256"] = hashlib.sha256(body.text.encode('utf-8')).hexdigest()
            target_dict["poll_ts"] = self.ts_now()
            target_dict["js_size"] = len(body.text)
            return target_dict
        except:
            logging.error("JsPollDB.return_target_hash: Unable to get content from {}".format(target_dict["url"]))
            
    def close(self):
        self.conn.close()
   
    def database_path(self):
        path = Path(__file__).resolve().parents[0] / "data" / "js_poller.sqlite3"
        if path.exists():
            return path
        else:
            logging.error("JsPollDb.init: {} does not exist".format(path))
            return None
    
    def filestore_path(self, filename):
        return Path(__file__).resolve().parents[0] / "raw" / filename

    def ts_now(self):
        return datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f%z')

x = JsPollDb(import_list=urls)



    


