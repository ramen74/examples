class Bike < ActiveRecord::Base
  #has_attached_file :photo
  
  has_and_belongs_to_many :parts
  
end
