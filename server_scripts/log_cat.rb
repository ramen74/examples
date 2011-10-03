#This script will go through the the formatted rails log files, aggregate errors and email the results.
#ruby log_cat -l error_log
#or to test ruby log_cat -c (see below for more info.
#To Add new "filters" of logs find the type of message and add it in the LogFilter class.
#originally created by Derek Szydlowski
require 'parsedate'
require 'singleton'

class InternalErrorHandler
#The idea here is that any exception that we handle in the log cat will get logged and sent with the email. If you dont get an email period
#then you know something is very very  wrong.

include Singleton

attr_accessor :internal_errors

def initialize
  @internal_errors = Array.new
end

def add_error(current_error)
   puts "Recording an internal log_cat error [#{current_error}]"
   @internal_errors << "Internal Log Cat Error #{current_error}"
end

def stop_reap
    #This will stop the reaper and send an alert email with any stored internal errors.
    email_obj = EmailHandler.new
    email_obj.add_email_message('THE LOG CAT HAS BEEN PREMATURELY STOPPED!!')
    unless InternalErrorHandler.instance.internal_errors.nil?
         email_obj.add_email_message(InternalErrorHandler.instance.internal_errors)
    end
    
    email_obj.send_email
    Process.exit
end
end

class LogFactory
  #this parses the concatanated log file and returns an array of log objects.

  attr_accessor  :log_array, :test_only
  
  def initialize
    @logfile_path = ""
    @logfile_name = "error_production.log.1"      
    #THIS is the main array of all entries
    @my_array =  ""
    @log_array = Array.new
    #if @hours_back_to_parse is greater then 0 then we will only reap the log that many hours
    #so default equals -1 means aggregate entire file
    @hours_back_to_parse = -1
    @test_only = false
  end 
  
  def parse_arguments(argv)
    usage = "log_analyzer -l logfile name -a use time not entire  -t hours back to read (only if -a is false)  -c test the filters"
    argv.each_with_index do |arg, x|
      case arg
      when "-l" #logfile
        @logfile_name = argv[x+1].to_s
        #when "-a" #entire file
        #  @parse_entire_file = false
      when "-t" #time
        @hours_back_to_parse = argv[x+1]
        @hours_back_to_parse = @hours_back_to_parse.to_i
      when "-c" #run test olny
        @test_only = true
        puts "Running tests only!"
      when "-u", "-h", "--help", "-?", "--?" #print usage
        $stdout.puts usage
        exit(0)
      when "-x"
        $stdout.puts " factor"
        exit(0)
      end
    end
  end

  def parse_logfile
    #parses the logfile backwards
    #this is the main that does.....
    #Open The file

    logfile_name = "#{@logfile_path}#{@logfile_name}"
    #puts "Beginning to parse the logfile #{logfile_name}"

    unless File.exists?(logfile_name)
      InternalErrorHandler.instance.add_error("Log Cat has failed to open #{logfile_name}. This file does not exist or is not readable")
      InternalErrorHandler.instance.stop_reap
      #creating a fake file to get through the rest so we can send out the email, need to think of a way to handle this failing
    else
      file = File.new(logfile_name, "r")
    end
      #Pack all the entries into some nice little hash
    @counter = 0
    @entry_count = 0

    buffer = ""
    new_entry = false
    #TODO: Check for mem size OR write to a file for processing as this may grow large
    entries = Array.new
    lines = file.readlines
    puts "Completed reading file into memory #{lines.length.to_s}"
    curLine = lines.size - 1

    #while (line = file.gets)
    while (curLine >= 0)
      line = lines[curLine]
      new_entry = check_new(line)

      if new_entry == true
        @counter = @counter + 1
        buffer = line + buffer
        #This gets rid of the error log header which is getting added to the error_logger.
        if buffer.include?("# Error Logfile created on")
          #buffer.gsub!([/\',""/)
          matchdata = buffer.match /\[/
          buffer = "[" + matchdata.post_match
        end
        #this could be refactored to use the LogFilter
        entry_counter, entry_pid, entry_level, entry_date = buffer.split(/\]\[|\]|\[/)
        #puts "Checking file for 'keeper' status"
        if (@hours_back_to_parse < 0 or entry_within_time_range?(entry_date, @hours_back_to_parse))
          #puts "."
          if keep_entry?(entry_level)
            entries.push [buffer, file.lineno]
          end
        else
          #dont need to read anymore since they're ali older than our time frame
          break
        end
        #empty buffer
        buffer = ""
      else
        buffer = (line + buffer) if !line.nil?
      end
      curLine = curLine - 1
    end

    while (e = entries.pop) != nil
      #puts "Adding message #{e[0]} #{e[1]}"
      add_entry_to_array(e[0], e[1])
    end
  end

  private

  def add_entry_to_array(entry, num)
    mylogobject = LogEntry.new("[#{num}]#{entry}")
    @log_array << mylogobject
  end
  
  def keep_entry?(entry_level)
    #while this should be error fatal will take any file and process
    #if entry_within_time_range?(entry_time) &&
    if (entry_level.eql?("ERROR") || entry_level.eql?("FATAL") || entry_level.eql?("SEVERE"))
      return true
    else
      return false
    end
  end
  
  def entry_within_time_range?(log_time, time_back)
    #if Time NOW in seconds since epoch minus Time of log in sec since epoch > seconds in an hour(or whatever time back)
    log_seconds_since_epoch = sqltime_to_time(log_time).to_i
    current_seconds_since_epoch = Time.now.to_i #dont worry about constant reassing of the time. Shouldnt matter that much
    seconds_back = time_back * 3600
    if (current_seconds_since_epoch - log_seconds_since_epoch < seconds_back.to_i)
      return true
    else  
      return false
    end
  end
  
  def check_new(stuff)
    #Broke this out for symplification .. kinda hokey. Needed for figuring out the start of the string since each
    #log span multiple lines
    #puts "checking for 'new' entry"
    if stuff =~ /\]\[SEVERE\]/ || stuff =~ /\]\[DEBUG\]/ || stuff =~ /\]\[ERROR\]/ || stuff =~ /\[FATAL\]/ || stuff =~ /\[INFO\]/ 
      return true
    else
      return false
    end
  end
  
  def sqltime_to_time(mysql_time)
    
    #note from dps: takes something like this from the log '2010-02-10 03:45:59'   and makes it like this 'Mon Dec 01 12:12:00 -0800 2008'
    #$stdout.puts mysql_time
    year, month, day, hour, min, sec = ParseDate.parsedate(mysql_time)
    #$stdout.puts "[#{year}][#{month}][#{day}][#{hour}][#{min}]"
    return Time.mktime(year, month, day, hour, min) 
  end

end

class LogEntry
  #This is the object each log should become some day when its been processed.
  
  attr_accessor  :original_message,  :msg_date, :msg_count, :msg_pid, :msg_level, :msg_message, :msg_type, :clean_message
  
  def initialize(message)
    break_log(message)
    thismessage = LogFilter.return_clean(@msg_message)
    #puts "DEBUG THIS MESSAGE:" + thismessage.to_s
    #this must return in order.... uh...
    @log_type = thismessage[0]
    @clean_message = thismessage[1]
    @original_message = message
  end
		
  def break_log(entry, type = 'all')
    junk, @msg_count, @msg_pid, @msg_level, @msg_date, @msg_message = entry.split(/\]\[|\]|\[/,6) # ][ or ] or [
  end

end	

class LogFilter
  #This 'cleans' up the logs. Removes variables etc.... Used by the filter.

  #This is for cutting out any matching regex and replacing with something of your choice.
  #remove these which are QBN errors
  #66.ticket.qbn.ie.intuit.com
  LINE_FILTERS = [
    [/(\d\d|\d\d\d|\d).ticket.qbn.ie.intuit.com/,"YYY.ticket.qbn.ie.intuit.com"],
    ## Filter this out incase its in a postError Logfile created on Mon Mar 08 01:45:19 -0800 2010
    [/#\sError\sLogFile\screated\son\s\w\w\w\s\w\w\w\s[0-3]\d\s[0-2]\d:\d\d:\d\d\s-\d\d\d\d\s\d\d\d\d/,"Error Logfile create on [xxxxxx]"],
    #filter out date
    [/\w\w\w\s\w\w\w\s\d\d\s\d\d\:\d\d:\d\d\s-\d\d\d\d\s\d\d\d\d/,"YYYYYYYYYY" ],
    [/[2]\d\d\d-[0-3][0-9]-[0-1][0-9]\s[0-2][0-4]:[0-6][0-9]:[0-6][0-9]/, "YYYYYYYYY" ],
    #filter out an IP Address in a post
    [/\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/,"xxx.xxx.xxx.xxx"],
    #filter out object  like SOAP::Mapping::Object:0x..fac3b5a2>
    [/Object:\S\S..\S\S\S\S\S\S\S\S/,"Object:YY..YYYYYYYY"],
    #filter out Search post index failyres like PostIndex failed for [4562 vehicl expens subject 2^misc deduct subject 2 percent incom]: 400 "Bad Request"
    #BTW This nifty expression matches anything between these two '[' ']' characters "\[(.*?)\]"
    [/PostIndex\sfailed\sfor\s\[(.*?)\]/,"PostIndex failed for [wwwwwwwwww]"],
    #unsubscribe: bogus reply id - a33tu-kp4r35ulab4lx-42
    [/unsubscribe:\sbogus\sreply\sid\s-\s\S{22}/,'unsubscribe: bogus reply id - [xxxxxxxxxxxxxxxxxxxxxx]'],
    #ApplicationLogic: create_user_record: couldnt set uid, ppid = 144896922
    [/ppid\s=\s\d{5,12}/,"ppid = [xxxxxxxxx]"],
    #Couldnt create user record in confirm_user_record_exists;ppid:144896922
    [/ppid:\d{5,12}/,"ppid:[xxxxxxxxxx]"],
    #nil parameter in create_ticket_hash_key: auth_id=91007942 agent_id= ticket=V1-198-cmK_jRRd2xEKsEd4Ri6g1w
    [/auth_id=\d{5,12}/,"auth_id=[xxxxxxxx]"],
    [/ticket=\S{29}/,"ticket=[xxxxxxxx]"],
    #Exception getting time ticket last validated: #<MemCache::MemCacheError: lost connection to ciaprodcache1.lc.intuit.com:11211>
    [/\w\w\wprodcache\d{1,3}/,"[YYY]prodcache[X]"],
    #NoMethodError (undefined method `add_omniture_beacon_header' for #<ReplyController:0xf57fa42c>): Bassically remove everything between ReplyController: and >
    [/<ReplyController:(.*?)>/,"<ReplyController:XXXXXXXXXX>"]

  ]

  REMOVE_BY_LINE = [
    #used to remove a line i.e. ruby stack trace line /usr/local
    "/usr/local", #get rid of less usefull stacktrace info
    "/vendor" #get rid of less usefull stack trace info
  ]

  #CUT_N_REPLACE_ENTIRE_MESSAGE = []
  #This filter is added below in the cut_n_replace entire_message method

  TEST_INPUTS = [
    #this should test the filters to use run log_cat with "-c"
    #[input string, expected output string]
    ['66.ticket.qbn.ie.intuit.com','YYY.ticket.qbn.ie.intuit.com'],
    #filter out a date in this format  Mon Mar 08 01:45:19 -0800 2010
    ['Today is Mon Mar 08 01:45:19 -0800 2010',"Today is YYYYYYYYYY",''],
    ['255.255.244.1','xxx.xxx.xxx.xxx'],
    ['255.3.244.255','xxx.xxx.xxx.xxx'],
    ['300.300.300.1','300.300.300.1'],
    ['PostIndex failed for [4562 vehicl expens subject 2^misc deduct subject 2 percent incom]: 400 "Bad Request"','PostIndex failed for [wwwwwwwwww]: 400 "Bad Request"'],
    ['unsubscribe: bogus reply id - a33tu-kp4r35ulab4lx-42','unsubscribe: bogus reply id - [xxxxxxxxxxxxxxxxxxxxxx]'],
    ['ApplicationLogic: create_user_record: couldnt set uid, ppid = 144896922','ApplicationLogic: create_user_record: couldnt set uid, ppid = [xxxxxxxxx]'],
    ['Couldnt create user record in confirm_user_record_exists;ppid:144896922','Couldnt create user record in confirm_user_record_exists;ppid:[xxxxxxxxxx]'],
    ['nil parameter in create_ticket_hash_key: auth_id=91007942 agent_id= ticket=V1-198-cmK_jRRd2xEKsEd4Ri6g1w','nil parameter in create_ticket_hash_key: auth_id=[xxxxxxxx] agent_id= ticket=[xxxxxxxx]'],
    ['Exception getting time ticket last validated: #<MemCache::MemCacheError: lost connection to ciaprodcache1.lc.intuit.com:11211>','Exception getting time ticket last validated: #<MemCache::MemCacheError: lost connection to [YYY]prodcache[X].lc.intuit.com:11211>'],
    ['SOAP::Mapping::Object:0x..fac3b5a2','SOAP::Mapping::Object:YY..YYYYYYYY'],
    ['  my name is     bob  ','my name is bob'],  #removing spaces, exercise generic filter
    ['/tax/cia/current/app','/tax/cia/current/app'],
    ["NoMethodError (undefined method `add_omniture_beacon_header' for #<ReplyController:0xf57fa42c>):","NoMethodError (undefined method `add_omniture_beacon_header' for #<ReplyController:XXXXXXXXXX>):"]
    #['/tax/cia/current/vendor/blah\nhello','hello']
  ]


  def self.return_clean(message)
    #figure out type to return to obj for informational purposes and for cut_n_replace organization
    #THIS is where the message gets passed through the 4 filters.
    msg_type = return_type(message)
    #start filtering: to add to the individual filters pick out the function: pass the message through each filter.
    filtered_message = String.new
    filtered_message = generic_filter(message)
    filtered_message = cut_n_replace_entire_message(filtered_message, msg_type)
    filtered_message = cut_n_replace_by_line(filtered_message)
    filtered_message = cut_n_replace_regex(filtered_message)
    return msg_type, filtered_message
  end


  private

  def self.generic_filter(new_message)
    #1)UNIQUE CLEANUP TASKS
    #Filter out weird characted etc we dont like like unnesesary white space.
    new_message.strip!
    #REMOVE MORE 2 or more whitespaces in a row (Looks messy) the .strip is redundant. may remove first
    new_message = new_message.squeeze(' ').strip
  end

  def self.cut_n_replace_by_line(new_message)
    #4) CUT OUT A "LINE" of a message based on text
    #used to remove a line i.e. ruby stack trace line /usr/local
    #TODO: slight concern the array may get reassembled in the wrong order.
    #SETUP

    unless REMOVE_BY_LINE.nil?
      REMOVE_BY_LINE.each do |line_removal_string|
        if new_message.include?(line_removal_string)
          msg_array = Array.new
          msg_array = new_message.split(/\n/)
          #EACH GETS SCREWED UP WHEN DOING A DELETE ON ITSELF.
          clean_string = String.new
          msg_array.each do |myline|
            if myline.include?(line_removal_string)
              #puts "tossing" + myline
            else
              #puts "keeping:" + myline
              clean_string = clean_string + myline + "\n"
            end
          end
          clean_string.strip!
          new_message = clean_string
        end
      end
    else
      internal_errors.add_error("NO BUT_N_REPLACE by line filters! This is unexpected")
    end
    return new_message
  end

  def self.cut_n_replace_entire_message(message, mytype)
    case
      #ACTIONCONTROLLER FILTERS
    when mytype.eql?('ActionController')
      if message.include?("ActionController::RoutingError (No route matches")
        new_message =  "ActionController::RoutingError (No route matches  [xxxxxxxxxx]"
      else
        new_message = message
      end
    when mytype.eql?('ActiveRecord')
      #ActiveRecord::RecordNotFound (Couldn't find Post with ID=cnsP9SkU0r35jkabHrYcN0):
      case
      when message.include?("ActiveRecord::RecordNotFound (Couldn't find Post with ID=")
        new_message = "ActiveRecord::RecordNotFound (Couldn't find Post with ID=[xxxxxxxxxxxxxxxxxx]"
      else
        new_message = message
      end
      #ACTIONVIEW FILTERS
    when mytype.eql?('ActionView')
      new_message = message
      #OTHER CUSTOM MESSAGES
    when mytype.eql?('OtherMessage')
      case
      when message.include?("show_post_full_view : Unable to locate post")
        new_message = "show_post_full_view : Unable to locate post with id = [xxxxxxxxx]"
      when message.include?("show_mini : Unable to locate post with id")
        new_message = "show_mini : Unable to locate post with id [xxxxxxxxxxxxx]"
      else
        new_message = message
      end
      #THIS SHOULD NOT HAPPEN!!
    else
      new_message = "ERROR IN LOG MESSAGE: Something has gone wrong in the LOG_CAT script!!"
      InternalErrorHandler.instance.add_error("Unknown message type. #{message}")
    end
    #puts "NEW MESSAGE:" + new_message
    if new_message.nil?
      InternalErrorHandler.instance.add_error("LogFilter has recieved a nil message!")
    end
    return new_message
  end
  
  def self.cut_n_replace_regex(new_message)
   
    #################################
    unless LINE_FILTERS.nil?
      LINE_FILTERS.each do |filter|
        new_message = new_message.gsub(filter[0], filter[1])
      end
    end
    return(new_message)
    #return mytype, new_message
  end

  def self.return_type(message)
    case
    when message.include?('ActiveRecord')
      return 'ActiveRecord'
    when message.include?('ActionController')
      return 'ActionController'
    when message.include?('ActionView')
      return 'ActionView'
    else
      return 'OtherMessage'
      #return "OTHER: " +message
    end
  end


  def self.test
    #Heres a place where you can run the rules and test so if you add new rules you dont break anything else, excute this test by running script with a parameter.
    TEST_INPUTS.each do |x|
      #puts x.inspect
      #puts "::#{x[0]} #{x[1]}"
      orig = x[0]
      exp_clean = x[1]
      real_clean = return_clean(orig)
      #output = cut_n_replace_regex(i[0])
      if real_clean[1] != exp_clean
        puts "Failed: [#{real_clean[1]}] Does not equal expected [#{exp_clean}] (original msg #{orig}"
        #.add_error("Failed: [#{real_clean[1]}] Does not equal expected [#{exp_clean}] (original msg #{orig}")
        #puts "Original equals [ #{orig}] "
      else
        #puts "Original [ #{orig}] "
        puts "Passed: [#{real_clean[1]}] Equals expected [#{exp_clean}] "   
      end
    end
  end
  
end

class AggregatedLog

  attr_accessor  :unique_log, :total_counts, :unique_array

  def initialize
    @unique_log = Hash.new
    @unique_array = Array.new
    #new [0]message, [1]count, [2]array of times, [3]array_of_servers, [4]average_per_server
  end
      
  def  process_message(log_message , log_date = "unknown", log_server = "unknown")
    #this only works now if unique info has been removed
    #go through all logs so far and see if its new
    entry_updated = false
    @unique_array.each do |entry|
      if log_message.eql?(entry[0])
         #update the entry 
         log_count = entry[1]
         #entry[0] is the messge there nothing to do
         entry[1] = log_count + 1
         entry[2] << log_date
         entry[3] << log_server
         entry_updated = true
      end
    end
    if entry_updated.eql?(false)
      #add new entry
      @unique_array << [log_message,1,[log_date],[log_server]]
    end

    unless @unique_log.has_key?(log_message)
      #add new entry
      @unique_log[log_message] = 1
    else
      #increment the count
      current_count = @unique_log[log_message]
      @unique_log[log_message] = current_count + 1
    end
    return_counts
  end
    
  def return_counts
    @unique_log.length.to_s
  end

  def sort_by_counts
    #need to figure out how to sort by an element in an array
    @unique_array = @unique_array.sort_by {|a| a[1]}
    @unique_array = @unique_array.reverse
    @unique_log = @unique_log.sort_by {|a,b| b}
    @unique_log = @unique_log.reverse
  end
    		
end

class EmailHandler
  #small refactor from the log reaper.. making email a seperate singleton

  def initialize
    @email_to = "dszydlowski@me.comm"
    #@mail_server = 'mxp.inf.com'
    @mail_server = 'mail.somewhere.com'
    @mail_port = '25'
    @send_on_error_only = true
    @my_hostname = `hostname`
    #creates the header
    @my_message =  ""
    @my_message += "<<END_OF_MESSAGE"
    @my_message += "To: #{@email_to}\n"
    @my_message += "From: server@server.com\n"
    @my_message += "Subject: LogNotification #{@my_hostname}\n"
    @my_message += "Auto Generated Fatal and Error Aggregator (log_cat.rb) \n \n"
    #@my_message += "Time Range: #{format_time(Time.now - 3600)} - #{format_time(Time.now)}\n"
  end

  def add_email_message(message)
    @my_message += message.to_s + "\n"
  end

  def send_email
    #@my_message += "Total Entries [#{@entry_count}] of [#{@counter}]\n"
    puts "Sending Email report"
    @my_message += "END_OF_MESSAGE"
    unless @send_on_error_only == true && @entry_count == 0
      #smtp mailing: This will be specific per environment... Should match environemnt.rb
      require 'net/smtp'
      $stdout.puts "Sending logs: Total Entries [#{@entry_count}] of [#{@counter}]."
      Net::SMTP.start(@mail_server, @mail_port, 'www.turbotax.com') do |smtp|
        smtp.send_message(@my_message, @email_to, @email_to)
        smtp.finish
      end
    else
      $stdout.puts "No Error Logs to Send: Total Entries" #[#{@entry_count}] of [#{@counter}]."
    end
  end      

end

############################################
#  This is the Beginning 
############################################

begin

  @test_only = ""
  truncate_at = 1000
  #TODO add hours to rate
  #hours_to_reap = 1
  #the metrics container keeps all the metrics
  #The Email Handler send out the email
  #the logfactory parses the logs and return an array of the log object

  #This commented out code would test if you can STOP the test midstream and get an email
  #InternalErrorHandler.instance.add_error("test error")
  #InternalErrorHandler.instance.stop_reap

  create_logs = LogFactory.new
  create_logs.parse_arguments(ARGV)
      
  if create_logs.test_only.eql?(true)
    LogFilter.test
    Process.exit
  else
    
    create_logs.parse_logfile

    log_objects = create_logs.log_array
    total_parsed_logs = log_objects.length

    #add all the objects to the stats and count them up
    metrics_container = AggregatedLog.new

    log_objects.each do |myobj|
      metrics_container.process_message(myobj.clean_message, myobj.msg_date)
    end
    #ALL DONE now spill out the results and email them...
    email_obj = EmailHandler.new
    total_unique_logs = metrics_container.return_counts
    #puts "TOTAL LOGS: [" +  total_parsed_logs.to_s + "]  TOTAL UNIQUE LOGS: [" + total_unique_logs.to_s + "]
    email_obj.add_email_message("TOTAL LOGS: [" +  total_parsed_logs.to_s + "]  TOTAL UNIQUE LOGS: [" + total_unique_logs.to_s + "]\n")
    metrics_container.sort_by_counts
    metrics_container.unique_array.each do |mycleanlog, mycount, mydates, myserver|
      #puts mycount.to_s + "+++++++++++++"
      #aggregated_log =  "[" + mycount.to_s + "] " + mycleanlog[0..truncate_at]
      my_aggregated_log =  "[" + mycount.to_s + "] " + mycleanlog.to_s
      puts my_aggregated_log + "\n"
      mydatessorted = mydates.sort
      #mydatessorted.each do |thedate|
      unless mydatessorted.length.eql?(1)
        mydate =  "Timestamp First [#{mydatessorted.first}] Last [#{mydatessorted.last}]"
      else
        mydate =  "Timestamp [#{mydatessorted.last}]"
      end
      puts mydate + "\n"
      #end
      
      unless my_aggregated_log.nil?
        email_obj.add_email_message(my_aggregated_log)
        email_obj.add_email_message(mydate + "\n")
      end
      #puts "COMPLETE"
    end
    unless InternalErrorHandler.instance.internal_errors.nil?
         email_obj.add_email_message(InternalErrorHandler.instance.internal_errors)
    end
    email_obj.send_email
  end
end
