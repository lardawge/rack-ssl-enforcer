require 'helper'

class TestRackSslEnforcer < Test::Unit::TestCase

  context 'that has no :redirect_to set' do
    setup { mock_app }

    should 'respond with a ssl redirect to plain-text requests' do
      get 'http://www.example.org/'
      assert_equal 301, last_response.status
      assert_equal 'https://www.example.org/', last_response.location
    end

    should 'respond with a ssl redirect to plain-text requests and keep params' do
      get 'http://www.example.org/admin?token=33'
      assert_equal 301, last_response.status
      assert_equal 'https://www.example.org/admin?token=33', last_response.location
    end

    #heroku / etc do proxied SSL
    #http://github.com/pivotal/refraction/issues/issue/2
    should 'respect X-Forwarded-Proto header for proxied SSL' do
      get 'http://www.example.org/', {}, { 'HTTP_X_FORWARDED_PROTO' => 'http', 'rack.url_scheme' => 'http' }
      assert_equal 301, last_response.status
      assert_equal 'https://www.example.org/', last_response.location
    end

    should 'respond not redirect ssl requests' do
      get 'https://www.example.org/'
      assert_equal 200, last_response.status
      assert_equal 'Hello world!', last_response.body
    end

    should 'respond not redirect ssl requests and respect X-Forwarded-Proto header for proxied SSL' do
      get 'http://www.example.org/', {}, { 'HTTP_X_FORWARDED_PROTO' => 'https', 'rack.url_scheme' => 'http' }
      assert_equal 200, last_response.status
      assert_equal 'Hello world!', last_response.body
    end

    should 'use default https port when redirecting non-standard http port to ssl' do
      get 'http://example.org:81/', {}, { 'rack.url_scheme' => 'http' }
      assert_equal 301, last_response.status
      assert_equal 'https://example.org/', last_response.location
    end

    should 'secure cookies' do
      get 'https://www.example.org/'
      assert_equal ["id=1; path=/; secure", "token=abc; path=/; secure; HttpOnly"], last_response.headers['Set-Cookie'].split("\n")
    end

    should 'not set default hsts headers to all ssl requests' do
      get 'https://www.example.org/'
      assert !last_response.headers["Strict-Transport-Security"]
    end

    should 'not set hsts headers to non ssl requests' do
      get 'http://www.example.org/'
      assert !last_response.headers["Strict-Transport-Security"]
    end
  end

  context 'that has :redirect_to set' do
    setup { mock_app :redirect_to => 'https://www.google.com' }

    should 'respond with a ssl redirect to plain-text requests and redirect to :redirect_to' do
      get 'http://www.example.org/'
      assert_equal 301, last_response.status
      assert_equal 'https://www.google.com', last_response.location
    end

    should 'respond not redirect ssl requests' do
      get 'https://www.example.org/'
      assert_equal 200, last_response.status
      assert_equal 'Hello world!', last_response.body
    end
  end

  context 'that has regex pattern as only option' do
    setup { mock_app :only => /^\/admin/ }

    should 'respond with a ssl redirect for /admin path' do
      get 'http://www.example.org/admin'
      assert_equal 301, last_response.status
      assert_equal 'https://www.example.org/admin', last_response.location
    end

    should 'respond not redirect ssl requests' do
      get 'http://www.example.org/foo'
      assert_equal 200, last_response.status
      assert_equal 'Hello world!', last_response.body
    end

    should 'secure cookies' do
      get 'https://www.example.org/'
      assert_equal ["id=1; path=/; secure", "token=abc; path=/; secure; HttpOnly"], last_response.headers['Set-Cookie'].split("\n")
    end
  end

  context 'that has path as only option' do
    setup { mock_app :only => "/login" }

    should 'respond with a ssl redirect for /login path' do
      get 'http://www.example.org/login'
      assert_equal 301, last_response.status
      assert_equal 'https://www.example.org/login', last_response.location
    end

    should 'respond not redirect ssl requests' do
      get 'http://www.example.org/foo/'
      assert_equal 200, last_response.status
      assert_equal 'Hello world!', last_response.body
    end
  end

  context 'that has array of regex pattern & path as only option' do
    setup { mock_app :only => [/\.xml$/, "/login"] }

    should 'respond with a ssl redirect for /login path' do
      get 'http://www.example.org/login'
      assert_equal 301, last_response.status
      assert_equal 'https://www.example.org/login', last_response.location
    end

    should 'respond with a ssl redirect for /admin path' do
      get 'http://www.example.org/users.xml'
      assert_equal 301, last_response.status
      assert_equal 'https://www.example.org/users.xml', last_response.location
    end

    should 'respond not redirect ssl requests' do
      get 'http://www.example.org/foo/'
      assert_equal 200, last_response.status
      assert_equal 'Hello world!', last_response.body
    end
  end

  context 'that has array of regex pattern & path as only option with strict option' do
    setup { mock_app :only => [/\.xml$/, "/login"], :strict => true }

    should 'respond with a http redirect from non-allowed https url' do
      get 'https://www.example.org/foo/'
      assert_equal 301, last_response.status
      assert_equal 'http://www.example.org/foo/', last_response.location
    end

    should 'respond from allowed https url' do
      get 'https://www.example.org/login'
      assert_equal 200, last_response.status
      assert_equal 'Hello world!', last_response.body
    end

    should 'use default https port when redirecting non-standard ssl port to http' do
      get 'https://example.org:81/', {}, { 'rack.url_scheme' => 'https' }
      assert_equal 301, last_response.status
      assert_equal 'http://example.org/', last_response.location
    end

    should 'secure cookies' do
      get 'https://www.example.org/login'
      assert_equal ["id=1; path=/; secure", "token=abc; path=/; secure; HttpOnly"], last_response.headers['Set-Cookie'].split("\n")
    end

    should 'not secure cookies' do
      get 'http://www.example.org/'
      assert_equal ["id=1; path=/", "token=abc; path=/; secure; HttpOnly"], last_response.headers['Set-Cookie'].split("\n")
    end
  end

  context 'that has :except option passed in' do
    setup { mock_app :except => [/^\/users$/] }

    should 'not redirect if GET https' do
      get 'https://www.example.org/users'
      assert_equal 200, last_response.status
      assert_equal 'Hello world!', last_response.body
    end

    should 'not redirect if GET http' do
      get 'http://www.example.org/users'
      assert_equal 200, last_response.status
      assert_equal 'Hello world!', last_response.body
    end
  end

  context 'that has mixed option set to true' do
    setup { mock_app :only => ['foo'], :mixed => true }

    should 'redirect if GET https' do
      get 'https://www.example.org/users'
      assert_equal 301, last_response.status
      assert_equal 'http://www.example.org/users', last_response.location
    end

    should 'not redirect if POST https' do
      post 'https://www.example.org/users'
      assert_equal 200, last_response.status
      assert_equal 'Hello world!', last_response.body
    end

    should 'not redirects if POST http' do
      post 'http://www.example.org/users'
      assert_equal 200, last_response.status
      assert_equal 'Hello world!', last_response.body
    end

    should 'redirect if GET https' do
      get 'https://www.example.org/users/123'
      assert_equal 301, last_response.status
      assert_equal 'http://www.example.org/users/123', last_response.location
    end

    should 'not redirect if PUT http' do
      put 'http://www.example.org/users/123'
      assert_equal 200, last_response.status
      assert_equal 'Hello world!', last_response.body
    end

    should 'not redirect if PUT https' do
      put 'https://www.example.org/users/123'
      assert_equal 200, last_response.status
      assert_equal 'Hello world!', last_response.body
    end

    should 'not redirect if DELETE http' do
      delete 'http://www.example.org/users/123'
      assert_equal 200, last_response.status
      assert_equal 'Hello world!', last_response.body
    end

    should 'not redirect if DELETE https' do
      delete 'https://www.example.org/users/123'
      assert_equal 200, last_response.status
      assert_equal 'Hello world!', last_response.body
    end
  end

  context 'that has hsts options set' do
    setup { mock_app :hsts => {:expires => '500', :subdomains => false} }

    should 'set expiry option' do
      get 'https://www.example.org/'
      assert_equal "max-age=500", last_response.headers["Strict-Transport-Security"]
    end

    should 'not include subdomains' do
      get 'https://www.example.org/'
      assert !last_response.headers["Strict-Transport-Security"].include?("includeSubDomains")
    end
  end

  context 'that has :hsts options set' do
    setup { mock_app :hsts => { :expires => '500', :subdomains => false } }

    should 'set expiry option' do
      get 'https://www.example.org/'
      assert_equal "max-age=500", last_response.headers["Strict-Transport-Security"]
    end

    should 'not include subdomains' do
      get 'https://www.example.org/'
      assert !last_response.headers["Strict-Transport-Security"].include?("includeSubDomains")
    end
  end

  context 'that has force_secure_cookie option set to false' do
    setup { mock_app :force_secure_cookies => false }

    should 'not secure cookies' do
      get 'https://www.example.org/users/123/edit'
      assert_equal ["id=1; path=/", "token=abc; path=/; secure; HttpOnly"], last_response.headers['Set-Cookie'].split("\n")
    end
  end

end
