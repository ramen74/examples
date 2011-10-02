#This "driver" is used to communicate  with a propriatary ID Manager rest service
#In order to use this driver you will do something like this: 
#@driver = AccessManagerRest.new
#then one of the three options:
#case 1 create new user
#@driver.create_idm_user({:login_name => "bob", :password => "super_secret", :email_address => "me@test.com", :security_question => "what is your pets name", :security_answer => "fido"})
#case 2 authenticate an existing user
#@driver.authenticate({:loginName => "bob", :password => "super_secret"}
#case 3 validate a security token of an authed user
#@driver.verify_ticket(<<some ticket returned from authenticate>>, <<user guid returned from authenticate>>, <<id from authenticate>>, <<ip address if returned>>)


class AccessManagerRest

  require 'net/https'
  require 'rexml/document'
  include REXML
  require 'openssl'
  require 'oauth'
  require 'singleton'

  def initialize
    #These endpoints are identified by the API doc at http://c00000012084.pharos.intuit.com:8180/job/gateway-nightly/ws/target/staging/service/apidocs/index.html
    @authenticate_endpoint = "/gateway-service-access-pox"
    @identity_endpoint = "/gateway-service-identity-pox"
  end

  def authenticate(params)
    
    #Get the user parameters
    username = params[:loginName]
    password = params[:password]
    
    #Now authenticate: IE login and get a ticket
    #URL as specified by IDManager team
    server = ACCESS_MANAGER_URL
    payload = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><token:authenticateInfo xmlns:token=\"http://schema.intuit.com/platform/access/token/v1\"> <credential><username>#{username}</username><password>#{password}</password><namespaceId>50000003</namespaceId></credential></token:authenticateInfo>"
    endpoint = @authenticate_endpoint + "/v1/authenticateService/authenticate"

    response = post(payload, endpoint, server)
    if response.nil?
      #this case can happen when IDManager is down
      idmanager_response = IdManagerResponse.new("Post Error", "500")
    else
      #parse the xml and return an IDMANAGER OBJECT. This object is designed to emulate the structure ofidmanager_response the previouse SOAP object
      idmanager_response = objectify_response(response.body, response.code)
    end
  end

  #for some reason the SOAP method wanted ip. I dont think it is used but taking it anyway becouse its being passed.
  def verify_ticket(securitytoken, authid, agentid, ip = nil)

     #URL and endpoint as specified by IDManager team
    server = ACCESS_MANAGER_URL
    endpoint = @authenticate_endpoint + "/v1/ticketService/verify"

    #note <valid> <realID> etc seem to have no use however it appears that the fields need to be passed empty regardless based on the documentation...
    payload = "<token:securityToken xmlns:token=\"http://schema.intuit.com/platform/access/token/v1\"><valid></valid><authId>#{authid}</authId><agentId>#{agentid}</agentId><namespaceId>50000003</namespaceId><realmId></realmId><credential>#{securitytoken}</credential><accessRight></accessRight></token:securityToken>"

    #deliver the message
    response = post(payload, endpoint, server)
    idmanager_response = objectify_response(response.body, response.code)

    #return a true or false 
    if idmanager_response.errorCode == '0'
      return true
    else
      return false
    end
  end

  def create(user_info)
  
    #URL and enpoint  as specified by IDManager team
    server = ACCOUNT_MANAGER_URL
    endpoint = @identity_endpoint + "/v1/userService/create"
    payload = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><user:user xmlns:user=\"http://schema.intuit.com/platform/identity/user/v1\"><username>#{user_info[:loginName]}</username><password>#{user_info[:password]}</password><email>#{user_info[:emailAddress]}</email><securityQuestion>#{user_info[:securityQuestion]}</securityQuestion><securityAnswer>#{user_info[:securityAnswer]}</securityAnswer></user:user>"
 
    response = post(payload, endpoint, server)
    
    #parse the xml and return an IDMANAGER OBJECT. This object is designed to emulate the structure ofidmanager_response the previouse SOAP object
    idmanager_response = objectify_response(response.body, response.code)
    return idmanager_response

  end

  private

  def objectify_response(response_xml = nil, response_code = nil)
    #This breaks out the xml response into a nice hash and eventually turns it in an idmanager object data structure.
    #certain error responses come back as a string and not xml.
      response  = Hash.new
  begin
      #prepare the XML for parsing
      xml_doc = Document.new response_xml
      root = xml_doc.root
      #turn each element into a key value pair (hash)
      #TODO: perhaps validate that a node is a leaf.
      root.elements.each do |field|
        response[field.name] = field.text
      end
  rescue
      #Handle the case where the API doesn't return valid xml in the response, usually due to a failure on their end
      response = "Failure reading response message from ID service"
      if response_code.nil?
        response_code = "404"
      end
      Rails.logger.error "failure reading response message from ID service"
  end
  #take the parsed xml and turn it into a SOAP datastructure
  idmanager_response = IdManagerResponse.new(response, response_code)
  return idmanager_response
  end

  def post(payload, endpoint, server)
     
     #To send an outh request you will need the folling from IDManager
     #1) consumer_key: a sting provided by IDManager.. its something like "OurCompany.cto.service.yourservice"
     #2) private_key: This is a string. IDManager will give youa Java Keystore file of OPENSSL key file. You will need to extract the private key from this.
     #3) company_id: Also a string provided by idmanager, something like "OurCompany.cto.yourservice"
     
    #Get the private key which is provided by IDMANAGER. 
    private_key = IdCert.instance.cert
    consumer_key = IDM_CONSUMER_KEY
    #using the oauth gem to do all the goodies like atually signing the call and sending the HTTP post
    consumer = OAuth::Consumer.new(
      consumer_key,
      private_key,
      :site => server,
      :timestamp => Time.now.to_i,
      :signature_method => "RSA-SHA1",
      :version => 1.0,
      :consumer_key => consumer_key,
      :http_method => :post
      #:intuit_appid => "iamintegration1",
      ###:intuit_offeringid => "compant.cto.livecommunity"
      )
      access_token = OAuth::AccessToken.new consumer
      begin
         #the oauth agteway we use requires "company_id" to be passed as well in the header per its spec.
         response = consumer.request(:post,  endpoint, access_token, {}, payload, {'Content-Type' =>'application/xml', 'company_id' => "OurCompany.cto.livecommunity"})
      rescue
         Rails.logger.fatal "failed to get a response from the ID service (IDManager)"
      end
      return response
  end

end

class IdManagerResponse

  def initialize(input_response = "", http_response = "")
    #need two things: the body and the response that usually  comes from an HTTP response object
    @response = input_response['responseCode']
    #@response should return a hash with keys of responseCode and responseMessage. Using reponseCode as it seems more appropriate.
    @http_response = http_response
  end
  
  #use method missing to pull the value from the response and create a dynamic getter...
  #doing this becouse we dont know all the fields that may be returned from a idmanager response and we want them accessable.
  def method_missing(method)
      return @response[method.to_s]
  end

  #this is a hack to fix a weird bug where in the debugger the word response was returning a corrupted data structure. Some how the method missing was screwing up the call.
  #this fixed that...  
  def response
      return @response
  end

  def ticket
    #handles the fact that for some reason Rest calls ticket and not security token now.
    return self.securityToken
  end
  
  def errorCode
    #seems like we got a 200 as a string and an int depending on the auth interface. handling this
     if @http_response == 200 || @http_response == "200"
        #previos interfaces wanted a response of 0. backwards compatibility with the soap interface
        @errorCode = "0"
     else
       if @response.nil?
      #Handle the case if the response is not 200 and there is no responseCode. This shouldnt happen but since we have no control over response we will handle the case. 
         @response  = "Unknown Error"
       end       
       #Translate some of the errors from the REST to SOAP code if needed, or just return the error.
        @errorCode = @response
     end
  end

end

class IdCert
  #making this a singleton so we don't keep opening and closing the file to read in the cert. 

  include Singleton

  attr_accessor :cert

  def initialize
    #TODO: read from some kind of a keystore instead of exposing the file in the code base
    begin
      @cert = IO.readlines(IDM_SIGNATURE_FILE).to_s
    rescue
      Rails.logger.debug "failed to open cert file for Oauth"
      raise
    end
  end

end
