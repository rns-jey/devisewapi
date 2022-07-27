class User < ApplicationRecord
  include Devise::JWT::RevocationStategies::JTIMatcher
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable, :trackable and :omniauthable
  devise :database_authenticatable, :registerable, :validatable, :recoverable, :rememberable,
         :jwt_authenticatable, jwt_revocation_stategy: self
end
