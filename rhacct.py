#!/usr/bin/env python
# Filename:                rhacct
# Description:             Adds users to Red Hat Portal
# Supported Platforms:     Python 2.4.x on RHEL5.10 and newer
# Time-stamp:              <2014-07-28 13:57:25 jfulton> 
# Author(s):               John Fulton <fulton@redhat.com>
# -------------------------------------------------------
# Copyright (c) 2014, John Fulton
# 
# This file is part of rhacct
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
# -------------------------------------------------------
# GLOBALS (add desc first for code reader)
desc = \
"""%prog: add users to or modify users in the Red Hat Customer
Portal. Uses email address to idenitfy user. Created username
is email address and password is default value. Assumes organizational
admin credentials are in /etc/%prog.conf. Otherwise prompts for
credentials.
"""
# These dictionaries map Strata API names to rhacct names
# This is done to make CLI options shorter
user_attrib = {'login':'email', # login=email for uniqueness \
               'email':'email',\
               'firstName':'first',\
               'lastName':'last',\
               'phoneNumber':'phone',\
               'createdDate':'created',\
               'lastLoggedInDate':'lastlogin',\
               'id':'id'
               }
# todo the API calls these roles, so the variable should be changed
permissions_map = {'portal_manage_cases':'cases', \
                   'portal_view_knowledge':'knowledge', \
                   'portal_manage_subscriptions':'subscritions', \
                   'portal_download':'downloads', \
                   'portal_access_group':'groups', \
                   'portal_system_management':'systems',\
                   } 
# Define permissions
permissions_def = { \
    'cases':'Allows user to manage support cases', \
    'knowledge':'Allows user to view knowledge base articles', \
    'subscritions':'Allows user to manage software subscriptions', \
    'downloads':'Allows user to download software', \
    'systems':'Allows user to manage systems',\
    'groups':'Allows user to manage groups', \
    } 
# -------------------------------------------------------
# Credentials to access the customer poral (don't set these here)
username = ''  # org-admin username of user running this script
password = ''  # org-admin password of user running this script
defpasswd = '' # password for new users created by this script
# This is the default URL that this script uses for the API 
# I don't expect user to know this so I set it to a default
url = 'https://api.access.qa.redhat.com' # remove qa when deplying
# Configuration file where the 4 vars above should be stored (try -g):
conf = '/etc/rhacct.conf'
# -------------------------------------------------------
import sys
import os
import urllib2
import pprint
# -------------------------------------------------------
# Functions below connect via Strata API to write to portal
# -------------------------------------------------------
def disable_user(email):
    """
    Function:                disable_user

    Description:             Disables a user by scrambling
                             his/her password and setting
                             all permissions to false

    Parameters:

    Return Values:           
       Boolean               True on sucess
                             False on failure

    Remarks:                 
       None                  
    """
    # ---------------------------------------------------
    # todo
    print "Disabling password for " + email + "... "

    return False
# -------------------------------------------------------
def modify_user(email, first, last, perms=[], verbose=False, keep=False):
    """
    Function:                create_user

    Description:             creates a user with permissions

    Parameters:
       [in] string email     Users email address
       (in) string first     Optional Users first name
                             (Default: empty string)
       (in) string last      Optional Users last name
                             (Default: empty string)
       (in) list perms       Optional list of permissions
                             (Default: empty list)
       (in) boolean keep     Optional flag to not disable other permissions
                             (Default: false)
       (in) boolean verbose  Optional flag to print verbose messages
                             (Default: false)

    Return Values:           
       Boolean               True on sucess
                             False on failure
    Remarks:                 
       None                  
    """
    # ---------------------------------------------------
    # todo
    # consider call to user_details(email)
    if verbose:
        print "Modifying '" + email + "'",
        print "with the permissions: " + ', '.join(perms)
        if keep:
            print "retaining existing permissions: ... "
    return False
# -------------------------------------------------------
def create_user(email, first, last, perms=[], verbose=False):
    """
    Function:                create_user

    Description:             creates a user with permissions

    Parameters:
       [in] string email     Users email address
       [in] string first     Users first name
       [in] string last      Users last name
       (in) list perms       Optional list of permissions
                             (Default: empty list)
       (in) boolean verbose  Optional flag to print verbose messages
                             (Default: false)

    Return Values:           
       Boolean               True on sucess
                             False on failure
    Remarks:                 
       * todo: the API calls to set permissions
       * todo: report on non-email address OK
       * create for email address must be valid email
       * todo: you cannot force the username to be email
    """
    # ---------------------------------------------------
    from urllib2 import HTTPError
    import re

    # 0. Make XML representing the user
    if verbose:
        print "Creating " + first + " " + last + " (" + email + ")",
        print "with the permissions: " + ', '.join(perms)
    global defpasswd
    user_dict = { \
      'email': email, # must be syntactically valid email 
      'firstName': first,
      'lastName': last,
      'login': email, # Should not be forced to email
      'password': defpasswd,
      'greeting':'Mr.', # mandatory #todo add to input
      'phoneNumber': '555-555-1212', # mandatory #todo add to input
      # the following are defaults
      'permissions': { 'allowEmailContact': 'true',
                       'allowMailContact': 'true'},
      'system': 'WEB', 
      'userType': 'P', 
      # API prefers these fields be present either filled in 
      # or 1 character strings but not omitted or empty strings
      'address': { 'address1': ' ',
                   'county': ' ',
                   'city': ' ',
                   'postalCode': ' ',
                   'countryCode': ' '},
    }
    data = user_dict_to_xml(user_dict, pretty_print=True)
    # 1. Create user
    user_created = False
    global url
    prep_urlopen() 
    headers = {'Content-Type': 'application/vnd.redhat.user+xml'} 
    path = "/rs/beta/users/"
    try:
        req = urllib2.Request(url+path, data, headers)  
        response = urllib2.urlopen(req)
        output = response.read()
        print output
    except HTTPError, http_status: 
        # Using old Python 2.4 exception handling 
        # If >2.4, I could have used HTTPError.getcode
        # When user is created correctly we get:
        #   'HTTP Error 201: Created'
        # Why does an "error" start with a 20x?
        # not sure; in HTTP 20x is good, moving on...
        http_status = str(http_status)
        HTTP_200 = re.compile(r"20[0-9]")
        if HTTP_200.search(http_status):
            user_created = True
            if verbose:
                # These are not necessarily errors; esp for 20x
                # user wants verbose, but don't want to mislead
                print "HTTP return: ",
                print str(http_status).replace('Error ','')
        else:
            print "HTTP return: " + http_status
    except:
        print "Unexpected error trying to post to API"
        if verbose:
            print "url: " + url+path
            print "headers: " + headers
            print "data: "  + data
    if not user_created:
        return False
    else: 
        # 2. Get user ID
        user_id = get_user_id_number(email)
        if verbose:
            print "Created user " + email,
            print "with user_id: " + str(user_id) 
        # 3. Update roles (aka permissions for now)
        # unless specified the default permissions are
        # cases,subscritions,downloads,systems
        # todo: HERE

    return False
# -------------------------------------------------------
# Functions below connect via Strata API to read from portal
# -------------------------------------------------------
def get_users(verbose=False):
    """
    Function:                get_users

    Description:             Prints a list of users

    Parameters:
       (in) verbose          Prints status messages
                             to stdout if True
                             (Default: False)

    Return Values:           
       None                  

    Remarks:                 
       None                  
    """
    # ---------------------------------------------------
    import simplejson as json
    account_id = str(get_account_number())
    if verbose:
        print "Getting all users for account: " + account_id
    global url
    prep_urlopen()
    path = "/rs/account/" + account_id + "/users" 
    data = None # Request will now use GET method  
    headers = {'Accept': 'application/json'}  

    # retrieve the data  
    req = urllib2.Request(url+path, data, headers)  
    response = urllib2.urlopen(req)  
    # display the results  
    output = response.read()
    if verbose:
            print 'sso_username' + ",",
            print 'first_name' + ",",
            print 'last_name' + ",",
            print 'org_admin'
    users = json.loads(output)['user']
    for user in users:
        try: 
            print user['sso_username'] + ",",
            print user['first_name'] + ",",
            print user['last_name'] + ",",
            print user['org_admin']
        except: #todo support unicode
            print "Warning: some unicode characters skipped"

# -------------------------------------------------------
def user_details(email, verbose=False):
    """
    Function:                user_details

    Description:             prints details about one user

    Parameters:
       [in] string $email    The email address of the user
       (in) verbose          Prints status messages
                             to stdout if True
                             (Default: False)

    Return Values:           
       None

    Remarks:                 
       None                  
    """
    # ---------------------------------------------------
    if verbose:
        print "Looking up details on " + email + "... "
    global url
    prep_urlopen()
    path = "/rs/beta/users/" + str(get_user_id_number(email))
    data = None # Request will now use GET method  
    headers = {'Accept': 'application/xml'}  
    req = urllib2.Request(url+path, data)
    response = urllib2.urlopen(req)  
    xml = response.read()
    attributes = user_xml_to_dict(xml) # does not get permissions
    global user_attrib
    for key, value in attributes.iteritems():
        if key in ['email','phoneNumber',\
                   'firstName', 'lastName', 
                   'createdDate', 'lastLoggedInDate']:
            try:
                print user_attrib[key] +": "+ str(value)
            except: #todo support unicode
                print "Warning: some unicode characters skipped"
    global permissions_map
    permissions = get_permissions(xml)
    perm_string = ""
    for permission in permissions:
        perm_string += permissions_map[permission] + "," 
    print "permissions: " + perm_string

# -------------------------------------------------------
def user_dict_to_xml(user_dict, pretty_print=False):
    """
    Function:                user_dict_to_xml

    Description:             Converts a dictionary 
                             defining a user to XML

    Parameters:
       [in] dictionary       user_dict: a dictionary 
                             representing a user 
       (in) boolean          pretty_print: should the 
                             returned XML be formatted
                             to be easier to read? 

    Return Values:           
       string                user_xml: A string in
                             XML format representing
                             a user

    Remarks:                 
       * should be re-written to go deeper via recursion
    """
    # ---------------------------------------------------
    from lxml import etree
    url_bare = "http://www.redhat.com/gss/strata"
    url = '{'+url_bare+'}'
    ns = dict(n = url)
    parent = etree.Element("user", xmlns=url_bare)  
    for key0, value0 in user_dict.iteritems():  
         if type(value0) is not dict:  
              child = etree.SubElement(parent, key0)  
              child.text = value0  
         else:  
              child = etree.Element(key0)  
              for key1, value1 in value0.iteritems():  
                   grand_child = etree.SubElement(child, key1)  
                   grand_child.text = value1  
              parent.append(child)  
    return etree.tostring(parent, pretty_print=pretty_print,
                          xml_declaration=True, encoding="UTF-8").strip()
# -------------------------------------------------------
def user_xml_to_dict(xml):
    """
    Function:                user_xml_to_dict

    Description:             Converts XML representing
                             a user into a dictionary

    Parameters:
       [in] string $xml      A string in XML format

    Return Values:           
       dictionary            A dictionary representing
                             the XML passed as input

    Remarks:                 
       * Doesn't go deep enough to get all attributes
    """
    # ---------------------------------------------------
    from lxml import etree
    import StringIO
    url_bare = "http://www.redhat.com/gss/strata"  
    url = '{'+url_bare+'}'  
    ns = dict(n = url)  
    tree = etree.parse(StringIO.StringIO(xml))
    user = dict()  
    children = tree.findall('*')
    for child in children:  
         if child.tag.replace(url,'') not in ['address','permissions','roles']:  
              user[child.tag.replace(url,'')] = child.text  
         else:  
              tmp = dict()  
              grand_children = child.findall('*')
              for grand_child in grand_children:  
                   tmp[grand_child.tag.replace(url,'')] = grand_child.text  
              user[child.tag.replace(url,'')] = tmp
    return user
# -------------------------------------------------------
def get_permissions(xml):
    """
    Function:                get_permissions

    Description:             Extracts list of permissions
                             from XML representing
                             a user 

    Parameters:
       [in] string $xml      A string in XML format

    Return Values:           
       list                  A dictionary representing
                             the XML passed as input

    Remarks:                 
       * roles is also a name for these permissions
    """
    # ---------------------------------------------------
    from lxml import etree
    import StringIO
    url_bare = "http://www.redhat.com/gss/strata"  
    url = '{'+url_bare+'}'  
    ns = dict(n = url)
    tree = etree.parse(StringIO.StringIO(xml))
    user = dict()  
    children = tree.findall('*')
    permissions = []
    for child in children:
        if child.tag.replace(url,'') == 'roles':
            roles = child.findall('*')
            for role in roles:
                role_attributes = role.findall('*')
                for role_attribute in role_attributes:
                    if role_attribute.tag.replace(url,'') == 'roleLabel':
                        permissions.append(role_attribute.text)
    return permissions
# -------------------------------------------------------
def get_account_number():
    """
    Function:                get_account_number

    Description:             Returns the account number
                             of the authenticated user

    Parameters:
       None
       
    Return Values:           
       interger              
                             0 if authentication failed
                             N>0 where N is the account
                             number 

    Remarks:                 
       None                  
    """
    # ---------------------------------------------------
    prep_urlopen() 
    path = "/rs/accounts"
    data = None # Request will now use GET method  
    req = urllib2.Request(url+path, data)  
    response = urllib2.urlopen(req)  
    return int(response.read())
# -------------------------------------------------------
def get_user_id_number(sso_username):
    """
    Function:                get_user_id_number

    Description:             Returns the user id number
                             given an sso username

    Parameters:
       None
       
    Return Values:           
       interger              
                             0 if authentication failed
                             N>0 where N is the user id 
                             number 

    Remarks:                 
       None                  
    """
    # ---------------------------------------------------
    user_id = 0
    global url
    prep_urlopen() 
    headers = {'Content-Type': 'application/vnd.redhat.user-filter+xml'}
    path = "/rs/beta/users/"
    # todo: clean this, raw XML up into lxml calls
    data = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    data += '<userFilter xmlns="http://www.redhat.com/gss/strata" >'
    data += '<userName>' + sso_username + '</userName>'
    data += '<ssoUserNameSearchType>' + 'exactMatch' + '</ssoUserNameSearchType>'
    data += '<start>' + str(0) + '</start>'
    data += '<count>' + str(1) + '</count>'
    data += '</userFilter>'
    req = urllib2.Request(url+path, data, headers)  
    response = urllib2.urlopen(req)  
    output = response.read()
    from lxml import etree
    import StringIO
    url_bare = "http://www.redhat.com/gss/strata"  
    stratta_url = '{'+url_bare+'}'  
    ns = dict(n = stratta_url)
    tree = etree.parse(StringIO.StringIO(output))
    children = tree.findall('*')
    for child in children:
        if child.tag.replace(stratta_url,'') == 'user':
            user_tags = child.findall('*')
            for user_tag in user_tags:
                if user_tag.tag.replace(stratta_url,'') == 'id':
                    user_id = int(user_tag.text)
    return user_id
# -------------------------------------------------------
def prep_urlopen(): 
    """
    Function:                prep_urlopen()

    Description:             prepares urllib2.urlopen()
                             function to use the username
                             and password defined in the
                             globals for authentication
                             and the global variable url

    Parameters:
       None

    Return Values:           
       None

    Remarks:                 
       * After this function is called, all calls to
         urllib2.urlopen will use handler defined below
       * Uses the globals for username, password, url
       * Created this so as to replace the same 8 lines
         with this one function call throughout the program. 
    """
    # ---------------------------------------------------
    # todo perhaps these shouldn't even be globals
    global username
    global password
    global url
    # create a password manager      
    passman = urllib2.HTTPPasswordMgrWithDefaultRealm()  
    # 1st argument of None means this username/password  
    # will be used for any path after the URL  
    passman.add_password(None, url, username, password)  
    # create the AuthHandler  
    authhandler = urllib2.HTTPBasicAuthHandler(passman)  
    # create the OpenerDirector
    opener = urllib2.build_opener(authhandler)  
    # all calls to urllib2.urlopen will now use this handler
    urllib2.install_opener(opener)  

# -------------------------------------------------------
# Functions below are for authentication including conf file
# -------------------------------------------------------
def get_credentials(generate_config=False):
    """
    Function:                get_credentials

    Description:             Sets the following globals
                               * username
                               * password
                               * url
                               * defpasswd
                             For each run of the program either 
                             by reading /etc/rhacct.conf xor 
                             by prompting for user input. 

    Parameters:
       Boolean               generate_config is True if user
                             wants to generate a configuration
                             file; i.e. they already passed
                             '-g' so do not remind them about it.

    Return Values:           
       Boolean               True if four variables above were 
                             set to strings of non-zero length
                             False if four varialbes were not 
                             set

    Remarks:                 
       Does /etc/rhacct.conf exist? If so parse for
       credentials and set the four global variables.
       If not, then prompt user for input. 
    """
    # ---------------------------------------------------
    global username
    global password
    global url
    global defpasswd
    try:
        os.stat(conf)
        username, password, url, defpasswd = cred_from_conf()
    except OSError:
        msg = conf +" does not exist, prompting for input."
        if not generate_config:
            msg += " See -g to prevent this."
        print msg
        username, password, url, defpasswd = prompt_for_cred()
    if len(username) > 0 and len(password) > 0 and \
           len(url) > 0 and len(defpasswd) > 0:
        # consider calling authentication test
        return True
    else:
        return False
# -------------------------------------------------------
def prompt_for_cred():
    """
    Function:                prompt_for_cred()

    Description:             Reads credentails from 
                             user input that it asks
                             for using getpass

    Parameters:
       None

    Return Values:
       sequence of strings   username, password, url, defpasswd

    Remarks:                 
       * Uses getpass
       * Functions that call this function should check if
       any of the returned strings are empty, as that would
       indicate that there is an error. 
    """
    # ---------------------------------------------------
    import getpass
    global url
    # not setting globals here, setting locals
    username = password = l_url = defpass = "" 
    try:
        msg = "Organization Administor username: "
        username = str(raw_input(msg))
        msg = "Organization Administor password: "
        password = str(getpass.getpass(prompt=msg))
        msg = "URL [" + url + "]: " # offer default 
        l_url = str(raw_input(msg))
        if len(l_url) is 0:
            l_url = url
        msg = "Password for new user: "
        defpasswd = str(getpass.getpass(prompt=msg))
    except ValueError:
        print "Invalid input"
    return username, password, l_url, defpasswd
# -------------------------------------------------------
def cred_from_conf():
    """
    Function:                cred_from_conf()

    Description:             Reads credentails from 
                             the configuration file 
                             defined by the global
                             conf var

    Parameters:
       None

    Return Values:
       sequence of strings   username, password, url, defpasswd

    Remarks:                 
       * Uses ConfigParser to extract values from conf file
       * Functions that call this function should check if
       any of the returned strings are empty, as that would
       indicate that there is an error. 
    """
    # ---------------------------------------------------
    username = password = url = defpasswd = ""
    global conf
    import ConfigParser
    Config = ConfigParser.ConfigParser()
    try:
        Config.read(conf)
        username = Config.get('rhacct','username') 
        password = Config.get('rhacct','password')
        url = Config.get('rhacct','url')
        defpasswd = Config.get('rhacct','defpasswd')
    except IOError, e:
        print "Unable to open " + conf + ": " + e.strerror
    except:
        print "Unexpected error trying to read " + conf
    return username, password, url, defpasswd
# -------------------------------------------------------
def generate_config():
    """
    Function:                generate_config()

    Description:             Generates a configuration
                             file rhacct.conf in 
                             current working directory. 

    Parameters:

    Return Values:           
       Boolean               
                             True if file created
                             False if file not created

    Remarks:                 
       * Expectation is that user will move file from
       current working directory to /etc/rhacct.conf
       * uses ConfigParser
    """
    # ---------------------------------------------------
    newconf = (os.getcwd() + "/rhacct.conf").replace('//','/')
    print "Generating configuration file: " + newconf
    import ConfigParser
    Config = ConfigParser.ConfigParser()
    try:
        cfgfile = open(newconf, 'w')
        Config.add_section('rhacct')
        username, password, url, defpasswd = prompt_for_cred()
        Config.set('rhacct','username', username)
        Config.set('rhacct','password', password)
        Config.set('rhacct','url', url)
        Config.set('rhacct','defpasswd', defpasswd)
        Config.write(cfgfile)
        cfgfile.close()
        print newconf + " has been created and can be moved to /etc/"
    except IOError, e:
        print "Unable to open " + newconf + ": " + e.strerror
    except:
        print "Unexpected error trying to create " + newconf

# -------------------------------------------------------
# Functions and main below are for handling user input
# If you are writing a program to use the above as a lib
# then you should only need the above; e.g.
#
# >>> execfile('/home/jfulton/bin/rhacct')
# >>> get_credentials()
# >>> print username
#
# -------------------------------------------------------
def explain_permissions():
    """
    Function:                explain_permissions

    Description:             Explains what permissions 
                             mean in the portal to the 
                             user. 

    Parameters:
       None                  

    Return Values:           
       String                String explaining permissions
                             in English

    Remarks:                 
       None                  
    """
    # ---------------------------------------------------
    import textwrap
    exp = "The Red Hat Customer Portal has the following user permissions:"
    exp = textwrap.dedent(exp) + "\n\n"
    i = 1
    for term, meaning in permissions_def.iteritems():
        exp += "  "+ str(i) +". " + term + ": " + meaning + "\n"
        i += 1
    exp += textwrap.dedent("""
    Any of the above can be combined into a comma separated list
    (no spaces) after the -p option to assign permissions to a user.
    For example, 'rhacct -p knowledge,cases user@example.com',
    would allow the user to read knowledge base articles and manage
    cases but not to downlad software, manage subscriptions, or any
    of the other permissions above. If a permission is not specified 
    then it is excluded, unless you use the -k option.""")  
    print exp
# -------------------------------------------------------
def valid_username(username):
    """
    Function:                valid_username

    Description:             Validates a username 
                             syntactically. 
    Parameters:
       string                username

    Return Values:           
       Boolean               returns True if username is valid
                             else False

    Remarks:                 
       None
    """
    return True # no requirements for now
    import re
    EMAIL_REGEX = re.compile(r"[^@]+@[^@]+\.[^@]+")
    if EMAIL_REGEX.match(username):
        return True
    else:
        return False
# -------------------------------------------------------
def get_arg_parser():
    """
    Function:                get_arg_parser

    Description:             Creates an optparse parser 
                             all of the options that rhacct
                             will need
    Parameters:
       None

    Return Values:           
       Object                as returned by OptionParser()

    Remarks:                 
      I created this function to set aside all of the add_option()
      calls so code reader can read main() below more easily. 
      Uses optparse in order to be backwards compatible to RHEL5
      as stated in business requirement.
    """
    # ---------------------------------------------------
    from optparse import OptionParser    
    usage = "usage: %prog [options] user@example.com"
    parser = OptionParser(usage=usage, description=desc)
    parser.add_option("-e", "--explain",
                      action="store_true", dest="explain_permissions", default=False,
                      help="Explains permissions; e.g. 'rhacct -e'")

    parser.add_option("-l", "--list",
                      action="store_true", dest="list_users", default=False,
                      help="Prints all users; e.g. 'rhacct -l'")

    parser.add_option("-r", "--report",
                      action="store_true", dest="user_details", default=False,
                      help="Prints details of USER; e.g. 'rhacct -r user@example.com'")

    parser.add_option("-d", "--disable",
                      action="store_true", dest="disable_user", default=False,
                      help="Disables user USER (users cannot be deleted); e.g. 'rhacct -d user@example.com'")

    parser.add_option("-m", "--modify",
                      action="store_true", dest="modify_user", default=False,
                      help="Modify an existing user USER; e.g. 'rhacct -m user@example.com -p knowledge'")

    parser.add_option("-f", "--first-name",
                      action="store", dest="first", default='',
                      help="Sets first name; e.g. 'rhacct -f Jane -m user@example.com'")
    parser.add_option("-s", "--surname",
                      action="store", dest="last", default='',
                      help="Sets surname name; e.g. 'rhacct -s Doe -m user@example.com'")

    parser.add_option("-c", "--create",
                      action="store_true", dest="create_user", default=False,
                      help="Create user USER; e.g. 'rhacct -p knowledge -f Jane -s Doe -c user@example.com'")

    parser.add_option("-p", "--perm",
                      action="store", dest="permissions", default='', 
                      help="(Re)Assigns permissions to USER; PERMISSIONS must be comma separated list of permissions (no spaces) see -e for permission names; all passed permissions are enabled; if permission not specified that permission is disabled; e.g. 'rhacct -p cases,knowledge -c user@example.com'")

    parser.add_option("-k", "--keep",
                      action="store_true", dest="keep_permissions", default=False,
                      help="Only used with -m and -p to not remove existing permissions; this option is good for adding an extra priviliege; e.g. 'rhacct -m user@example.com -k -p downloads'")

    parser.add_option("-g", "--generate-config",
                     action="store_true", dest="generate_config", default=False,
                     help="Generate config file (rhacct.conf) in current working directory which can be stored in /etc/rhacct.conf. If said file is present rhacct will not prompt for input each time it is run.")


    # parser.add_option("-o", "--output",
    #                  action="store", dest="format", default='CSV',
    #                  help="Output format: CSV (default), JSON, XML; e.g. 'rhacct -o JSON -r user@example.com'")

    parser.add_option("-v", "--verbose",
                      action="store_true", dest="verbose", default=False,
                      help="Print status messages to stdout")
    return parser

# -------------------------------------------------------

if __name__ == "__main__":
    # store user input in options and args
    parser = get_arg_parser()    
    (options, args) = parser.parse_args()
    # all code below just parses user input and calls functions above
    if len(args) is 0:
        # if no argument was passed, should only be -e xor -l xor -h
        if len(options.last) + len(options.first) + len(options.permissions) > 0 \
           or options.user_details or options.disable_user or options.create_user \
           or options.modify_user or options.keep_permissions:
            parser.error("Unsupported option(s)")
        if options.explain_permissions and not options.list_users and not options.generate_config:
            explain_permissions()
        elif options.list_users and not options.explain_permissions and not options.generate_config:
            # authenticate first
            get_credentials(options.generate_config)
            get_users(options.verbose)
        elif options.generate_config and not options.list_users and not options.explain_permissions:
            generate_config()
        elif options.explain_permissions and options.list_users and options.generate_config:
            parser.error("Unsupported option(s)")
        else: # if -h or no argument and no option, then they need help
            parser.print_help()
    elif len(args) > 1:
        parser.error("Too many arguments passed")
    elif len(args) is 1: # should only be email address
        if not valid_username(args[0]):
            parser.error("'"+args[0]+"' is not a valid username")
        else: 
            email = args[0]
            # we must have at least one boolean or string option
            have_string = have_true = False
            for key, opt in options.__dict__.iteritems():
                if type(opt) is str:
                    if len(opt) > 0:
                        have_string = True
                elif type(opt) is bool:
                    if opt is True:
                        have_true = True
            if not have_string and not have_true:
                parser.error("No options were specified")
            elif options.disable_user + options.create_user + \
                     options.modify_user + options.user_details > 1:
                # only one of the above can be true (True is 1 so you can sum them)
                parser.error("Specified options cannot all be used at the same time")
            else:
                if options.user_details:
                    get_credentials(options.generate_config) # authenticate
                    user_details(email)
                elif options.disable_user:
                    if not disable_user(email):
                        sys.exit("error: failed to disable: "+email)
                    elif options.verbose:
                        print email+" has been disabled"
                elif options.modify_user:
                    if len(options.permissions) + len(options.first) \
                           + len(options.last) is 0:
                        parser.error("No modification options specified")
                    else:
                        permissions = options.permissions.split(',')
                        permissions = filter(None, permissions) # remove empty strings
                        for permission in permissions:
                            if permission not in permissions_def:
                                parser.error("'"+permission+"' is not a valid permission")
                        get_credentials(options.generate_config) # authenticate
                        if not modify_user(email, options.first, options.last, \
                                           permissions, options.verbose, \
                                           options.keep_permissions):
                            sys.exit("error: failed to modify: "+email)
                        elif options.verbose:
                            print email+" has been modified"
                elif options.create_user:
                    if len(options.first) is 0:
                        parser.error("First name cannot be excluded")
                    elif len(options.last) is 0:
                        parser.error("Surname cannot be excluded")
                    if len(options.permissions) is 0:
                        if options.verbose:
                            print "warning: creating "+email+" without any permissions"
                        permissions = []
                    else:
                        permissions = options.permissions.split(',')
                        permissions = filter(None, permissions) # remove empty strings
                        for permission in permissions:
                            if permission not in permissions_def:
                                parser.error("'"+permission+"' is not a valid permission")
                    get_credentials(options.generate_config) # authenticate
                    if not create_user(email, options.first, options.last, \
                                       permissions, options.verbose):
                        sys.exit("error: failed to create: "+email)
                    elif options.verbose:
                        print email+" has been created"
                else:
                    parser.error("Unsupported option")
