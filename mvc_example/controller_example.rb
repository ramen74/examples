#This is just an example of a method in the main controller that will render all bike in inventory 

  def bikes
 
    #get the rolling images ("grabbags") for the main "rolling banner".
    @grabbags = Grabbag.all(:conditions => ["content_type = 'rolling_banner'"])
 
    #this lets the users sort by price or date.
    @sort_order = "price"
    order = Bike::SORT_COLUMNS["date"]
    dir = "asc"
    dir = "desc" if (params[:d].eql?("up"))

    if dir.eql?("asc")
      @sort_dir = "&or;"
    else
      @sort_dir = "&and;"
    end
    
    if (Bike::SORT_COLUMNS.keys.include?(params[:c]))
      order = Bike::SORT_COLUMNS[params[:c]]
      @sort_order = params[:c]
    end
    
     @bikes = Bike.paginate :page => params[:page], :per_page => 25, :conditions => [%Q((status = 3 and updated_at > date_sub(curdate(), interval 1 month)) or  status != 3)],
      :order => " #{order} #{dir}"

  end
