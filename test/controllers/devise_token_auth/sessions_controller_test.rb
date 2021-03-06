require 'test_helper'

#  was the web request successful?
#  was the user redirected to the right page?
#  was the user successfully authenticated?
#  was the correct object stored in the response?
#  was the appropriate message delivered in the json payload?

class DeviseTokenAuth::SessionsControllerTest < ActionController::TestCase
  describe DeviseTokenAuth::SessionsController, "Confirmed user" do
    before do
      @existing_user = users(:confirmed_email_user)
      @existing_user.skip_confirmation!
      @existing_user.save!
    end

    describe 'success' do
      before do
        xhr :post, :create, {
          email: @existing_user.email,
          password: 'secret123'
        }

        @user = assigns(:user)
        @data = JSON.parse(response.body)
      end

      test "request should succeed" do
        assert_equal 200, response.status
      end

      test "request should return user data" do
        assert_equal @existing_user.email, @data['data']['email']
      end
    end

    describe 'failure' do
      before do
        xhr :post, :create, {
          email: @existing_user.email,
          password: 'bogus'
        }

        @user = assigns(:user)
        @data = JSON.parse(response.body)
      end

      test "request should fail" do
        assert_equal 401, response.status
      end

      test "response should contain errors" do
        assert @data['errors']
      end
    end
  end

  describe DeviseTokenAuth::SessionsController, "Unconfirmed user" do
    before do
      @unconfirmed_user = users(:unconfirmed_email_user)
      xhr :post, :create, {
        email: @unconfirmed_user.email,
        password: 'secret123'
      }
      @user = assigns(:user)
      @data = JSON.parse(response.body)
    end

    test "request should fail" do
      assert_equal 401, response.status
    end

    test "response should contain errors" do
      assert @data['errors']
    end
  end

  describe DeviseTokenAuth::SessionsController, "Non-existing user" do
    before do
      xhr :post, :create, {
        email: -> { Faker::Internet.email },
        password: -> { Faker::Number.number(10) }
      }
      @user = assigns(:user)
      @data = JSON.parse(response.body)
    end

    test "request should fail" do
      assert_equal 401, response.status
    end

    test "response should contain errors" do
      assert @data['errors']
    end
  end
end
