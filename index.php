<?php

/**
 * Plugin Name: New REST API Plugin
 * Plugin URI: https://www.exmapleplugin@restapi.com/plugin
 * Author: DP
 * Author URI: https://www.exmaplepluginauthor@restapi.com/
 * Description: This plugin contains All rest api routes
 * Version: 1.0.0
 * 
 */

require_once(ABSPATH . 'wp-admin/includes/file.php');
require_once(ABSPATH . 'wp-admin/includes/media.php');
require_once(ABSPATH . 'wp-admin/includes/image.php');

use firebase\JWT\JWT;
use firebase\JWT\KEY;

class CRC_REST_API extends WP_REST_Controller
{
    private $api_namespace;
    private $api_version;
    public  $user_token;
    public  $user_id;
    public  $post_id;


    public function __construct()
    {
        $this->api_namespace = 'api/v';
        $this->api_version = '1';
        $this->init();
        /*------- Start: Validate Token Section -------*/
        $headers = getallheaders();
        if (isset($headers['Authorization'])) {
            if (preg_match('/Bearer\s(\S+)/', $headers['Authorization'], $matches)) {
                $this->user_token =  $matches[1];
            }
        }
        /*------- End: Validate Token Section -------*/
    }


    //function to reset rest_api_init header cros 
    public function init()
    {
        add_action('rest_api_init', array($this, 'register_routes'));
        add_action('rest_api_init', function () {
            remove_filter('rest_pre_serve_request', 'rest_send_cors_headers');
            add_filter('rest_pre_serve_request', function ($value) {
                header('Access-Control-Allow-Origin: *');
                header('Access-Control-Allow-Methods: POST, GET, OPTIONS, PUT, DELETE');
                header('Access-Control-Allow-Credentials: true');
                return $value;
            });
        }, 15);
        /*------- Start: Validate Token Section -------*/
        $headers = getallheaders();
        if (isset($headers['Authorization'])) {
            if (preg_match('/Bearer\s(\S+)/', $headers['Authorization'], $matches)) {
                $this->user_token =  $matches[1];
            }
        }
        /*------- End: Validate Token Section -------*/
    }

    //function to register routes
    public function register_routes()
    {
        $namespace = $this->api_namespace . $this->api_version;
        $publicIteams = array(
            'register',
            'createPost',
            'forgetPassword',
            'verifyOTP',
            'resetPassword',
            'updateProfile',
            'updateProfile2',
            'createPost2',
            'getPosts',
            'getUser',
            'createBookPost',
            'updatePost',
            'createProduct',
            'quiz'
        );
        foreach ($publicIteams as $Iteam) {
            register_rest_route(
                $namespace,
                '/' . $Iteam,
                array(
                    array(
                        'methods' => 'POST',
                        'callback' => array($this, $Iteam),
                        'permission_callback' => '__return_true'
                    )
                )
            );
        }
    }



    public function successResponse($message = '', $data = [])
    {
        $response = array();
        $response['status'] = "success";
        $response['message'] = $message;
        $response['data'] = $data;



        return new WP_REST_Response($response, 200);
    }


    public function errorResponse($message = '', $type = 'ERROR', $status_code = 400)
    {
        $response = array();
        $response['status'] = 'error';
        $response['error_type'] = $type;
        $response['message'] = $message;

        return new WP_REST_Response($response, $status_code);
    }

    //function for user jwt_auth on user login  
    public function jwt_auth($data, $user)
    {
        unset($data['user_nicename']);
        unset($data['user_display_name']);
        $result = $this->getProfile($user->ID);
        $result['token'] =  $data['token'];
        return $this->successResponse('User Logged in successfully', $result);
    }

    //function to return user id for valid token
    public function getUserIdByToken($token)
    {
        $decoded_array = array();
        $user_id = 0;
        if ($token) {
            try {
                $decoded = JWT::decode($token, new Key(JWT_AUTH_SECRET_KEY, apply_filters('jwt_auth_algorithm', 'HS256')));
                $decoded_array = (array)$decoded;
                if (count($decoded_array) > 0) {
                    $user_id = $decoded_array['data']->user->id;
                }
                if ($this->user_id_exists($user_id)) {
                    return $user_id;
                } else {
                    return false;
                }
            } catch (\Exception $e) { // Also tried JwtException
                return false;
            }
        }
    }

    //function to check user id exists in db or not
    public function user_id_exists($user)
    {
        global $wpdb;
        $count = $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM $wpdb->users WHERE ID = %d", $user));
        if ($count == 1) {
            return true;
        } else {
            return false;
        }
    }

    //to register user
    public function register($request)
    {

        $param = $request->get_params();
        $role = 'customer';
        if (empty($param['username'])) {
            return $this->errorResponse('Please enter username');
        }
        if (username_exists($param['username'])) {
            return $this->errorResponse('Username already exists');
        }
        if (empty($param['email'])) {
            return $this->errorResponse('Please enter username');
        }
        if (email_exists($param['email'])) {
            return $this->errorResponse('Email already exists');
        }
        if (empty($param['password'])) {
            return $this->errorResponse('Please enter password');
        }
        if (empty($param['confirmpassword'])) {
            return $this->errorResponse('Please enter confirm password');
        }
        if (($param['password']) != ($param['confirmpassword'])) {
            return $this->errorResponse('Password does not match.');
        }
        $user_id = wp_create_user($param['username'], $param['password'], $param['email']);
        $user = new WP_User($user_id);
        $role = 'customer';
        $user->set_role($role);

        update_user_meta($user_id, 'nicename', $param['first_name']);
        update_user_meta($user_id, 'full_name', trim($param['first_name'] . ' ' . $param['last_name']));
        update_user_meta($user_id, 'first_name', $param['first_name']);
        update_user_meta($user_id, 'last_name', $param['last_name']);
        update_user_meta($user_id, 'company_id', $param['company_id']);
        update_user_meta($user_id, 'location_name', $param['location_name']);

        update_user_meta($user_id, 'status', 'Pending');

        $data = $this->getProfile($user_id);

        if (!empty($user_id)) {

            return $this->successResponse('User registered successfully', $data);
        } else {

            return $this->errorResponse('Error User not registered');
        }
    }

    //get user details
    public function getProfile($user_id)
    {
        $user = get_user_by('id', $user_id);

        if (!$user) {
            return $this->errorResponse('Error user profile not found', 404);
        }

        $profile = array(
            'id' => $user->ID,
            'username' => $user->user_login,
            'email' => $user->user_email,
            'full_name' => get_user_meta($user_id, 'full_name', true),
            'first_name' => get_user_meta($user_id, 'first_name', true),
            'last_name' => get_user_meta($user_id, 'last_name', true),
            'company_id' => get_user_meta($user_id, 'company_id', true),
            'location_name' => get_user_meta($user_id, 'location_name', true),
            'status' => get_user_meta($user_id, 'status', true),
            'user_role' => get_user_meta($user_id, 'wp_capabilities', true),
            'profile_image' => wp_get_attachment_image_url(get_user_meta($user_id, 'profile_image', true), 'thumbnail')
        );
        return $profile;
    }


    //forgetPassword function to verify email to get otp 
    public function forgetPassword($request)
    {
        $param = $request->get_params();
        $email = !empty($param['email']) ? sanitize_email($param['email']) : '';

        if (empty($email)) {
            return $this->errorResponse('Please enter email');
        }

        if (email_exists($email)) {
            $user = get_user_by('email', $email);
            $verify_email['success'] = 'Email has been verified successfully';
            $otp = rand(100000, 999999);
            $user_id = $user->ID;
            update_user_meta($user_id, 'password_reset_otp', $otp);
            update_user_meta($user_id, 'otp_experation_time', time() + 100);
            $verify_email['One Time Password'] = "Your OTP is: " . $otp;
        } else {
            $verify_email = $this->errorResponse("You're email is not registered");
        }
        return $verify_email;
    }

    //function to verify OTP
    public function verifyOTP($request)
    {
        $param = $request->get_params();
        $email = !empty($param['email']) ? sanitize_email($param['email']) : $this->errorResponse('Please enter email for verification');
        $otp = !empty($param['otp']) ? sanitize_text_field($param['otp']) : $this->errorResponse('Please enter otp for verification');
        $user = get_user_by('email', $email);
        $user_id = $user->ID;
        $password_reset_otp = get_user_meta($user_id, 'password_reset_otp', true);
        $otp_experation_time = get_user_meta($user_id, 'otp_experation_time', true);

        if (time() > $otp_experation_time) {

            return $this->errorResponse('OTP has expired. Please request a new one.');
        } else {
            if ($otp && $otp === $password_reset_otp) {
                return $this->successResponse('OTP has been verified. You can now reset your password.');
            } else {
                return $this->errorResponse("Invaild OTP . Please try again");
            }
        }
    }


    //function to set user resetPassword
    public function resetPassword($request)
    {
        $param = $request->get_params();
        $email = !empty($param['email']) ? sanitize_email($param['email']) : $this->errorResponse("Please enter email for verification");
        $user = get_user_by('email', $email);
        $user_id = $user->ID;
        $new_password = !empty($param['new_password']) ? sanitize_text_field($param['new_password']) : $error = ($this->errorResponse("Please enter email for verification"));
        delete_user_meta($user_id, 'password_reset_otp');
        delete_user_meta($user_id, 'otp_experation_time');
        wp_set_password($new_password, $user_id);
        if (!empty($error)) {
            return $error;
        } else {
            return $this->successResponse('Password Changed Successfully');
        }
    }


    //function to check validity of token and 
    //for valid token sets user_id 
    private function isValidToken()
    {
        $this->user_id  = $this->getUserIdByToken($this->user_token);
    }



    //function to update profile
    public function updateProfile($request)
    {
        $param = $request->get_params();
        $email = isset($param['email']) ? sanitize_email($param['email']) : '';
        $first_name = isset($param['first_name']) ? sanitize_text_field($param['first_name']) : '';
        $last_name = isset($param['last_name']) ? sanitize_text_field($param['last_name']) : '';
        $full_name = $first_name . ' ' . $last_name;
        $company_id = isset($param['company_id']) ? sanitize_text_field($param['company_id']) : '';
        $location_name = isset($param['location_name']) ? sanitize_text_field($param['location_name']) : '';
        $this->isValidToken();
        $user_id = !empty($this->user_id) ? $this->user_id : false;

        if (!is_email($email)) {
            return $this->errorResponse('invalid_email', 'Invalid email address');
        }

        if ($user_id) {

            $user_data = array(
                'ID' => $user_id,
                'user_email' => $email,
                'first_name' => $first_name,
                'last_name' => $last_name
            );

            wp_update_user($user_data);
            update_user_meta($user_id, 'full_name', $full_name);
            update_user_meta($user_id, 'company_id', $company_id);
            update_user_meta($user_id, 'location_name', $location_name);

            if (isset($_FILES['profile_image']) && !empty($_FILES['profile_image']['name'])) {

                $file_nameExplode = explode('.', $_FILES['profile_image']['name']);
                $file_extension = strtolower(end($file_nameExplode));
                $file_size = $_FILES['profile_image']['size'];
                $accepted_filetype = array('jpeg', 'jpg', 'png');
                if (in_array($file_extension, $accepted_filetype)) {
                    if ($file_size > 2097152) {
                        return $this->errorResponse('File too large. File must be less than 2MB.');
                    } else {
                        $uploaded = wp_handle_upload($_FILES['profile_image'], array('test_form' => false));
                        if ($uploaded && !isset($uploaded['error'])) {


                            $attachment = array(
                                'guid' => $uploaded['url'],
                                'post_mime_type' => $uploaded['type'],
                                'post_title'     => sanitize_file_name($uploaded['file']),
                                'post_content'   => '',
                                'post_status'    => 'inherit',
                            );


                            // Insert the attachment into the media library
                            $attachment_id = wp_insert_attachment($attachment, $uploaded['file']);

                            // Generate attachment metadata and update the attachment
                            $attach_data = wp_generate_attachment_metadata($attachment_id, $uploaded['file']);

                            wp_update_attachment_metadata($attachment_id, $attach_data);

                            update_user_meta($user_id, 'profile_image', $attachment_id);
                        }
                    }
                } else {
                    return $this->errorResponse('File type not acceptable', 'Please Upload JPG , JPEG and PNG image file');
                }
            }


            $result['profile_data'] = $this->getProfile($user_id);
            return $this->successResponse('User Profile Updated successfully.', $result);
        } else {
            return $this->errorResponse('Invalid user, please login again.');
        }
    }


    //update profile function here profile image taken as base64 encoded input form
    public function updateProfile2($request)
    {
        $param = $request->get_params();
        $email = isset($param['email']) ? sanitize_email($param['email']) : '';
        $first_name = isset($param['first_name']) ? sanitize_text_field($param['first_name']) : '';
        $last_name = isset($param['last_name']) ? sanitize_text_field($param['last_name']) : '';
        $full_name = $first_name . ' ' . $last_name;
        $company_id = isset($param['company_id']) ? sanitize_text_field($param['company_id']) : '';
        $location_name = isset($param['location_name']) ? sanitize_text_field($param['location_name']) : '';
        $this->isValidToken();
        $user_id = !empty($this->user_id) ? $this->user_id : false;

        if (!is_email($email)) {
            return $this->errorResponse('invalid_email', 'Invalid email address');
        }

        if ($user_id) {

            $user_data = array(
                'ID' => $user_id,
                'user_email' => $email,
                'first_name' => $first_name,
                'last_name' => $last_name
            );

            wp_update_user($user_data);
            update_user_meta($user_id, 'full_name', $full_name);
            update_user_meta($user_id, 'company_id', $company_id);
            update_user_meta($user_id, 'location_name', $location_name);

            if (isset($param['profile_image_base64']) && !empty($param['profile_image_base64'])) {
                $attachment_id = $this->upload_profile_image_base64($param['profile_image_base64']);

                update_user_meta($user_id, 'profile_image', $attachment_id);
                $result['profile_data'] = $this->getProfile($user_id);
                return $this->successResponse('User Profile Updated successfully.', $result);
            } else {
                return $this->errorResponse('Please enter base64 image DATA URI');
            }
        } else {
            return $this->errorResponse('Invalid user, please login again.');
        }
    }

    //function to upload base64 encoded profile image
    public  function upload_profile_image_base64($base64_image)
    {
        if (preg_match('/^data:image\/(\w+);base64,/', $base64_image, $type)) {
            $upload_dir         =   wp_upload_dir();
            $base64             =   explode(';base64', $base64_image);
            $decoded            =   base64_decode($base64[1]);
            $filename           =   'profile_image';
            $file_type          =   strtolower($type[1]);;
            $hashed_filename    =   md5($filename . microtime()) . '.' . $file_type;

            if (file_put_contents($upload_dir['path'] . '/' . $hashed_filename, $decoded) === false) {
                return $this->errorResponse('file_save_failed', 'Failed to save the file.');
            }


            $attachment         =   array(
                'post_mime_type' => 'image/' . $file_type,
                'post_title'     =>  basename($hashed_filename),
                'post_content'   => '',
                'post_status'    => 'inherit',
                'guid'           => $upload_dir['url'] . '/' . basename($hashed_filename)
            );

            $attach_id = wp_insert_attachment($attachment, $upload_dir['path'] . '/' . $hashed_filename);
            $attach_data = wp_generate_attachment_metadata($attach_id, $upload_dir['path'] . '/' . $hashed_filename);
            wp_update_attachment_metadata($attach_id, $attach_data);
            return $attach_id;
        } else {
            return $this->errorResponse('invalid_base64', 'Invalid Base64 image format.');
        }
    }


    //function to creat book posts
    public function createBookPost($request)
    {

        $this->isValidToken();
        $user_id = !empty($this->user_id) ? $this->user_id : false;
        $param = $request->get_params();
        $title = isset($param['title']) ? sanitize_text_field($param['title']) : '';
        $content = isset($param['content']) ? sanitize_text_field($param['content']) : '';
        $author_name = isset($param['author_name']) ? sanitize_text_field($param['author_name']) : '';
        $publisher_name = isset($param['publisher_name']) ? sanitize_text_field($param['publisher_name']) : '';
        $book_price = isset($param['book_price']) ? round(floatval($param['book_price'])) : '';
        $book_genre = isset($param['book_genre']) ? sanitize_text_field($param['book_genre']) : '';
        $publication_date = isset($param['publication_date']) ? sanitize_text_field($param['publication_date']) : '';
        $book_isbn = isset($param['book_isbn']) ? sanitize_text_field($param['book_isbn']) : '';
        $cover_image = isset($param['cover_image']) ? sanitize_text_field(($param['cover_image'])) : '';
        $total_pages = isset($param['total_pages']) ? intval($param['total_pages']) : '';
        $book_language = isset($param['book_language']) ? sanitize_text_field($param['book_language']) : '';
        $book_format = isset($param['book_format']) ? sanitize_text_field($param['book_format']) : '';
        $book_rating = isset($param['book_rating']) ? sanitize_text_field($param['book_rating']) : '';
        $short_description = isset($param['short_description']) ? sanitize_text_field($param['short_description']) : '';

        if (
            empty($title) || empty($content) || empty($author_name) ||
            empty($publisher_name) || empty($book_price) || empty($book_genre) ||
            empty($publication_date) || empty($book_isbn) || empty($cover_image) ||
            empty($total_pages) || empty($book_language) || empty($book_format) ||
            empty($book_rating) || empty($short_description)
        ) {
            return $this->errorResponse('Error empty input field value not Acceptable', 'Please Enter all fields');
        }


        if ($user_id) {



            $args = [
                'post_author' => $user_id,
                'post_type' => 'book',
                'post_title' => $title,
                'post_content' => $content,
                'post_status' => 'publish',
            ];

            $post_id = wp_insert_post($args);
            if (!$post_id) {

                return $this->errorResponse('Post not created.', 'Error Post can not be instered ');
            }

            $attachment_id = $this->upload_post_image_base64($cover_image, $post_id);

            update_post_meta($post_id, 'author_name', $author_name);
            update_post_meta($post_id, 'publisher_name', $publisher_name);
            update_post_meta($post_id, 'book_price', $book_price);
            update_post_meta($post_id, 'book_genre', $book_genre);
            update_post_meta($post_id, 'publication_date', $publication_date);
            update_post_meta($post_id, 'book_isbn', $book_isbn);
            update_post_meta($post_id, 'cover_image', $attachment_id);
            update_post_meta($post_id, 'total_pages', $total_pages);
            update_post_meta($post_id, 'book_language', $book_language);
            update_post_meta($post_id, 'book_format', $book_format);
            update_post_meta($post_id, 'book_rating', $book_rating);
            update_post_meta($post_id, 'short_description', $short_description);

            $post = get_post($post_id);

            $result = $this->getBookDetails($post);

            return $this->successResponse("Post Created Successfully", $result);
        } else {
            return $this->errorResponse('Invaild User', 'Token Expired', 401);
        }
    }

    //After inserting book post get book details function
    private function getBookDetails($post)
    {
        $response = [
            'Post' => [
                'ID' => $post->ID,
                'Title' => $post->post_title,
                'Content' => $post->post_content,
                'Date' => $post->post_date,

            ],
            'Meta' => [
                'Author_Name' => get_post_meta($post->ID, 'author_name', true),
                'Book_Publisher_Name' => get_post_meta($post->ID, 'publisher_name', true),
                'Book_Price' => get_post_meta($post->ID, 'book_price', true),
                'Book_Genre' => get_post_meta($post->ID, 'book_genre', true),
                'Publication_Date' => get_post_meta($post->ID, 'publication_date', true),
                'Book_ISBN' => get_post_meta($post->ID, 'book_isbn', true),
                'Total_Pages' => get_post_meta($post->ID, 'total_pages', true),
                'Book_Language' => get_post_meta($post->ID, 'book_language', true),
                'Book_Format' => get_post_meta($post->ID, 'book_format', true),
                'Book_Rating' => get_post_meta($post->ID, 'book_rating', true),
                'Short_Description' => get_post_meta($post->ID, 'short_description', true),
                'Cover_Image' => wp_get_attachment_image_url(get_post_meta($post->ID, 'cover_image', true)),
            ],
        ];

        return  $response;
    }

    //function to create post
    public function createPost($request)
    {
        $param = $request->get_params();
        $this->isValidToken();
        $user_id = !empty($this->user_id) ? $this->user_id : false;
        $names = is_array($param['names']) ? $param['names'] : json_decode($param['names'], true);
        $typos = is_array($param['types']) ? $param['types'] : json_decode($param['types'], true);
        $catergory_ids = is_array($param['category_ids']) ? $param['category_ids'] : json_decode($param['category_ids'], true);
        $post_ids = is_array($param['posts_id']) ? $param['posts_id'] : json_decode($param['posts_id'], true);
        $post_object = is_array($param['post_object']) ? $param['post_object'] : json_decode($param['post_object'], true);

        if (
            empty($param['title']) || empty($param['content']) || empty($param['product_sku']) || empty($param['product_price']) ||
            empty($param['category_ids']) || empty($param['product_description']) || empty($param['customer_password']) || empty($param['product_image_base64']) ||
            empty($param['product_stock_status']) || empty($param['product_available_color']) || empty($param['product_type']) ||
            empty($param['customer_support_review']) || empty($param['product_release_date']) || empty($param['customer_email'])  || empty($param['product_url']) || empty($param['names']) || empty($param['types'])
        ) {
            return $this->errorResponse('Please input all fields', "Don't leave title and content field empty");
        }


        if (!empty($user_id)) {
            $args = [
                'post_author' => $user_id,
                'post_title' => $param['title'],
                'post_status' => 'publish',
                'post_content' => $param['content'],
                'post_type' => 'product_type',
            ];



            $post_id = wp_insert_post($args);

            if (!$post_id) {

                return $this->errorResponse('Post not created.', 'Error Post can not be instered ');
            } else {

                wp_set_object_terms($post_id, $catergory_ids, 'product_category');
            }

            $attachment_id = $this->upload_post_image_base64($param['product_image_base64'], $post_id);

            update_post_meta($post_id, 'product_sku', $param['product_sku']);
            update_post_meta($post_id, 'product_price', $param['product_price']);
            update_post_meta($post_id, 'product_description', $param['product_description']);
            update_post_meta($post_id, 'product_stock_status', $param['product_stock_status']);
            update_post_meta($post_id, 'product_available_color', $param['product_available_color']);
            update_post_meta($post_id, 'product_type', $param['product_type']);
            update_post_meta($post_id, 'customer_support_review', $param['customer_support_review']);
            update_post_meta($post_id, 'product_release_date', $param['product_release_date']);
            update_post_meta($post_id, 'customer_email', $param['customer_email']);
            update_post_meta($post_id, 'customer_password', $param['customer_password']);
            update_post_meta($post_id, 'product_url', $param['product_url']);
            update_post_meta($post_id, '_thumbnail_id', $attachment_id);

            update_field('query_question_1', $param['question_1'], $post_id);
            update_field('query_answer_1', $param['answer_1'], $post_id);
            update_field('query_question_2', $param['question_2'], $post_id);
            update_field('query_answer_2', $param['answer_2'], $post_id);


            update_field('book_product', $post_ids, $post_id);
            update_field('post_object', $post_object, $post_id);

            for ($i = 0; $i < max(count($names), (count($typos))); $i++) {
                update_post_meta($post_id, 'name_' . ($i + 1), $names[$i]);
                update_post_meta($post_id, 'typo_' . ($i + 1), $typos[$i]);
            }


            // Get the post object
            $post = get_post($post_id);

            $result = $this->product_details($post, $post->ID);


            return $this->successResponse('Post created  successfully.', $result);
        } else {
            return $this->errorResponse('Invalid User', 'TOKEN_EXPIRE', 401);
        }
    }


    public function upload_post_image_base64($post_image_base64, $post_id)
    {
        if ($post_image_base64) {
            if (preg_match('/^data:image\/(\w+);base64,/', $post_image_base64, $type)) {
                $file_type = strtolower($type[1]);
                $base64 = explode(';base64', $post_image_base64);
                $decoded = base64_decode($base64[1]);
                $upload_dir = wp_upload_dir();
                $upload_path = $upload_dir['path'];
                $file_name = 'product_image';
                $hased_filename = md5($file_name . microtime()) . '.' . $file_type;
                $accepted_filetype = ['png', 'jpeg', 'jpg'];
                if (!in_array($file_type, $accepted_filetype)) {
                    return $this->errorResponse('Invalid file type', 'Only JPEG and  PNG, images are allowed');
                }
                if ((file_put_contents($upload_path . '/' . $hased_filename, $decoded)) !== false) {

                    $attachment = array(
                        'guid' => $upload_dir['url'] . '/' . $hased_filename,
                        'post_mime_type' => 'image/' . $file_type,
                        'post_title' => basename($hased_filename),
                        'post_content' => '',
                        'post_status'    => 'inherit',
                        'post_parent' => $post_id
                    );

                    $attach_id = wp_insert_attachment($attachment, $upload_path . '/' . $hased_filename, $post_id);
                    if ($attach_id) {


                        $attach_data = wp_generate_attachment_metadata($attach_id, $upload_path . '/' . $hased_filename);
                        wp_update_attachment_metadata($attach_id, $attach_data);

                        return $attach_id;
                    } else {
                        return $this->errorResponse('Error while creating attachment');
                    }
                } else {
                    return $this->errorResponse('Error while uploading file', 'Please try again');
                }
            } else {
                return $this->errorResponse('Invalid base64', 'Invalid Encoded base64  ');
            }
        }
    }


    //function to get product details
    public function product_details($post, $post_id)
    {

        $response = [
            'Post' => [
                'ID' => $post->ID,
                'Title' => $post->post_title,
                'Content' => $post->post_content,
                'Date' => $post->post_date,

            ],
            'Meta' => [
                'Product_SKU' => get_post_meta($post_id, 'product_sku', true),
                'Product_Price' => get_post_meta($post_id, 'product_price', true),
                'Product_Description' => get_post_meta($post_id, 'product_description', true),
                'Product_Stock_Status' => get_post_meta($post_id, 'product_stock_status', true),
                'Product_Available_Color' => get_post_meta($post_id, 'product_available_color', true),
                'Product_Type' => get_post_meta($post_id, 'product_type', true),
                'Customer_Support_Review' => get_post_meta($post_id, 'customer_support_review', true),
                'Customer_Email' => get_post_meta($post_id, 'customer_email', true),
                'Customer_Password' => get_post_meta($post_id, 'customer_password', true),
                'Product_URL' => get_post_meta($post_id, 'product_url', true),
                'Product Release Date' => get_post_meta($post_id, 'product_release_date', true),
                'Product Image' => wp_get_attachment_image_url(get_post_meta($post_id, '_thumbnail_id', true)),
            ],

        ];
        $names = [];
        $index = 1;
        while ($name_value = get_post_meta($post->ID, 'name_' . $index, true)) {
            $names[] = $name_value;
            $index++;
        }

        $typos = [];
        $index = 1;
        while ($typo_value = get_post_meta($post->ID, 'typo_' . $index, true)) {
            $typos[] = $typo_value;
            $index++;
        }

        $response['Names'] = $names;
        $response['Types'] = $typos;
        return  $response;
    }


    //function to get users posts
    public function getPosts()
    {
        $this->isValidToken();
        $user_id = !empty($this->user_id) ? $this->user_id : false;

        if ($user_id) {

            $args = [
                'author' => $user_id,
                'post_status' => 'publish',
                'post_type' => 'product',
                'posts_per_page' => -1
            ];


            $posts_array = get_posts($args);
            $i = count($posts_array);
            foreach ($posts_array as $post) {
                $result['product' . ' ' . $i] = $this->product_details($post, $post->ID);
                $i--;
            }

            return  $this->successResponse('Post displaying successfully.', $result);
        } else {
            return $this->errorResponse('Invalid user token,Token expired.');
        }
    }


    public function updatePost($request)
    {
        $param = $request->get_params();
        $this->isValidToken();
        $user_id = !empty($this->user_id) ? $this->user_id : false;
        $names = is_array($param['names']) ? $param['names'] : json_decode($param['names'], true);
        $typos = is_array($param['types']) ? $param['types'] : json_decode($param['types'], true);
        $catergory_ids = is_array($param['category_ids']) ? $param['category_ids'] : json_decode($param['category_ids'], true);
        $post_ids = is_array($param['posts_id']) ? $param['posts_id'] : json_decode($param['posts_id'], true);
        $post_object = is_array($param['post_object']) ? $param['post_object'] : json_decode($param['post_object'], true);


        if (
            empty($param['post_id']) || empty($param['title']) || empty($param['content']) || empty($param['product_sku']) || empty($param['product_price']) ||
            empty($param['category_ids']) || empty($param['product_description']) || empty($param['customer_password']) || empty($param['product_image_base64']) ||
            empty($param['product_stock_status']) || empty($param['product_available_color']) || empty($param['product_type']) ||
            empty($param['customer_support_review']) || empty($param['product_release_date']) || empty($param['customer_email'])  || empty($param['product_url']) || empty($param['names']) || empty($param['types'])
        ) {
            return $this->errorResponse('Please input all fields', "Don't leave title and content field empty");
        }


        if ($user_id) {
            $args = [
                'ID' => $param['post_id'],
                'post_title' => $param['title'],
                'post_content' => $param['content'],
            ];

            if (is_wp_error(wp_update_post($args))) {

                return $this->errorResponse('Error While Updating Posting', 'Please try again');
            } else {
                wp_set_object_terms($param['post_id'], $catergory_ids, 'product_category');

                $attachment_id = $this->upload_post_image_base64($param['product_image_base64'], $param['post_id']);

                update_post_meta($param['post_id'], 'product_sku', $param['product_sku']);
                update_post_meta($param['post_id'], 'product_price', $param['product_price']);
                update_post_meta($param['post_id'], 'product_description', $param['product_description']);
                update_post_meta($param['post_id'], 'product_stock_status', $param['product_stock_status']);
                update_post_meta($param['post_id'], 'product_available_color', $param['product_available_color']);
                update_post_meta($param['post_id'], 'product_type', $param['product_type']);
                update_post_meta($param['post_id'], 'customer_support_review', $param['customer_support_review']);
                update_post_meta($param['post_id'], 'product_release_date', $param['product_release_date']);
                update_post_meta($param['post_id'], 'customer_email', $param['customer_email']);
                update_post_meta($param['post_id'], 'customer_password', $param['customer_password']);
                update_post_meta($param['post_id'], 'product_url', $param['product_url']);
                update_post_meta($param['post_id'], '_thumbnail_id', $attachment_id);

                update_field('book_product', $post_ids, $param['post_id']);
                update_field('post_object', $post_object, $param['post_id']);
                update_sub_field(['query', 'question_1'], $param['question_1'], $param['post_id']);
                update_sub_field(['query', 'answer_1'], $param['answer_1'], $param['post_id']);

                for ($i = 0; $i < max(count($names), (count($typos))); $i++) {
                    update_post_meta($param['post_id'], 'name_' . ($i + 1), $names[$i]);
                    update_post_meta($param['post_id'], 'typo_' . ($i + 1), $typos[$i]);
                }


                // Get the post object
                $post = get_post($param['post_id']);

                $result = $this->product_details($post, $post->ID);

                return $this->successResponse('Post Updated Successfully', $result);
            }
        } else {
            return $this->errorResponse('Invalid User', 'Token Expired', 402);
        }
    }


    public function createProduct($request)
    {
        $param = $request->get_params();

        if (isset($param['product_id']) && !empty($param['product_id'])) {
            $product = wc_get_product($param['product_id']);
        } else {
            $product = new WC_Product_Variable();
        }

        $product->set_name($param['name']);
        $product->set_status($param['status']);
        $product->set_catalog_visibility($param['catalog_visibility']);
        $product->set_description($param['description']);
        $product->set_short_description($param['short_description']);
        $product->set_sku($param['sku']);
        $product->set_price(0);
        $product->set_regular_price($param['regular_price']);
        $product->set_manage_stock(true);
        $product->set_stock_quantity($param['stock_quantity']);

        if (!empty($param['cat_ids'])) {
            $category_ids = is_array($param['cat_ids']) ? $param['cat_ids'] : json_decode($param['cat_ids'], true);
            $product->set_category_ids($category_ids);
        }



        if (isset($param['image_base64'])) {
            $image_ids = [];
            foreach ((array) $param['image_base64'] as $base64_encode) {
                $attachment_id = $this->upload_profile_image_base64($base64_encode);
                if ($attachment_id) {
                    $image_ids[] = $attachment_id;
                }
            }

            if (!empty($image_ids)) {
                $product->set_image_id($image_ids[0]);
                array_shift($image_ids);
                $product->set_gallery_image_ids($image_ids);
            }
        }


        if (isset($param['attributes'])) {
            $attributes = [];
            foreach ($param['attributes'] as $name => $options) {
                $attribute = new WC_Product_Attribute();
                $attribute->set_name($name);
                $attribute->set_options($options);
                $attribute->set_position(1);
                $attribute->set_visible(true);
                $attribute->set_variation(true);
                $attributes[] = $attribute;
            }
            $product->set_attributes($attributes);
        }

        $product->save();

        if (isset($param['variations'])) {
            foreach ($param['variations'] as $variation_data) {
                $this->saveProductVariation($product->get_id(), $variation_data);
            }
        }

        $result = $this->get_variable_product_details($product->get_id());
        return $this->successResponse("Product Created Successfully", $result);
    }


    private function saveProductVariation($product_id, $variation_data)
    {

        if (isset($variation_data['id'])) {
            $variation = wc_get_product($variation_data['id']);
            if (!$variation || $variation->get_type() !== 'variation') {
                return $this->errorResponse("Variation not found", "Invalid Variation ID");
            }
        } else {
            $variation = new WC_Product_Variation();
            $variation->set_parent_id($product_id);
        }

        $variation->set_attributes($variation_data['attributes']);
        $variation->set_sku($variation_data['sku']);
        $variation->set_regular_price($variation_data['regular_price']);
        $variation->set_sale_price($variation_data['sale_price']);
        $variation->set_weight($variation_data['weight']);
        $variation->set_length($variation_data['length']);
        $variation->set_width($variation_data['width']);
        $variation->set_height($variation_data['height']);

        if (!empty($variation_data['image_base64'])) {
            $image_id = $this->upload_profile_image_base64($variation_data['image_base64']);
            $variation->set_image_id($image_id);
        }

        if (isset($variation_data['manage_stock']) && $variation_data['manage_stock']) {
            $variation->set_manage_stock(true);
            $variation->set_stock_quantity($variation_data['stock_quantity']);
            $variation->set_stock_status('instock');
        } else {
            $variation->set_manage_stock(false);
        }

        $variation_id = $variation->save();
        return $variation_id ? $variation_id : $this->errorResponse("Error saving variation", "Unable to save variation");
    }

    private function get_variable_product_details($product_id)
    {
        $product = wc_get_product($product_id);

        if ($product && $product->is_type('variable')) {
            $product_data = array(
                'ID' => $product->get_id(),
                'Name' => $product->get_name(),
                'Description' => $product->get_description(),
                'Short Description' => $product->get_short_description(),
                'SKU' => $product->get_sku(),
                'Price' => $product->get_price(),
                'Stock Status' => $product->get_stock_status(),
                'Attributes' => $product->get_attributes(),
                'Image' => wp_get_attachment_url($product->get_image_id())
            );

            $variation_ids = $product->get_children();
            if (empty($variation_ids)) {
                return $this->errorResponse("No variations found for this product.");
            }

            $variation_data = array();

            foreach ($variation_ids as $variation_id) {
                $variation_product = wc_get_product($variation_id);
                $variation_data[] = array(
                    'Variation ID' => $variation_product->get_id(),
                    'Attributes' => $variation_product->get_attributes(),
                    'Regular Price' => $variation_product->get_regular_price(),
                    'Sale Price' => $variation_product->get_sale_price(),
                    'SKU' => $variation_product->get_sku(),
                    'Stock Status' => $variation_product->get_stock_status(),
                    'Weight' => $variation_product->get_weight(),
                    'Height' => $variation_product->get_height(),
                    'Width' => $variation_product->get_width(),
                    'Length' => $variation_product->get_length()
                );
            }

            $response = array();
            $response['product_data'] = $product_data;
            $response['variation_data'] = $variation_data;

            return $response;
        } else {
            return $this->errorResponse("Product not found or is not a variable product.");
        }
    }


    public function quiz()
    {

        $questions = [];
        $number = 1;

        while (get_field("question_{$number}", 88)) {

            $question = get_field("question_{$number}", 88);
            $answer_choices   = get_field_object("answer_choices_{$number}", 88)['choices'];
            $correct_answer = get_field_object("correct_answer_{$number}", 88)['value'];

            if (!$question && !$answer_choices) {
                break; // Exit loop if no more questions or answers are found
            }

            $questions[] = [
                'question' => $question,
                'answer_choices'   => $answer_choices,
                'correct_answer'   => $correct_answer,
            ];

            $number++;
        }

        if (empty($questions)) {
            return new WP_Error('no_questions_found', 'No questions found for this post.', ['status' => 404]);
        }

        return rest_ensure_response($questions);
    }


    
}


$serverApi = new CRC_REST_API();
add_filter('jwt_auth_token_before_dispatch', array($serverApi, 'jwt_auth'), 10, 2);







<?php
/**
 * Plugin Name: Custom WP REST API 
 * Author : Divyank
 */

use Firebase\JWT\JWT;
use \Firebase\JWT\Key;

require_once(ABSPATH . 'wp-admin/includes/file.php');
require_once(ABSPATH . 'wp-admin/includes/media.php');
require_once(ABSPATH . 'wp-admin/includes/image.php');

define('SITE_URL', site_url());

class CRC_REST_API extends WP_REST_Controller
{
    private $api_namespace;
    private $api_version;
    public  $user_token;
    public  $user_id;

    public function __construct()
    {
        $this->api_namespace = 'api/v';
        $this->api_version = '1';
        $this->required_capability = 'read';
        $this->init();

        /*------- Start: Validate Token Section -------*/
        $headers = getallheaders();
        if (isset($headers['Authorization'])) {
            if (preg_match('/Bearer\s(\S+)/', $headers['Authorization'], $matches)) {
                $this->user_token =  $matches[1];
            }
        }
        /*------- End: Validate Token Section -------*/
    }

    private function successResponse($message = '', $data = array())
    {
        $response = array();
        $response['status'] = "success";
        $response['message'] = $message;
        $response['data'] = $data;

        return new WP_REST_Response($response, 200);
    }

    private function errorResponse($message = '', $type = 'ERROR', $statusCode = 400)
    {
        $response = array();
        $response['status'] = "error";
        $response['error_type'] = $type;
        $response['message'] = $message;

        return new WP_REST_Response($response, $statusCode);
    }

    public function register_routes()
    {
        $namespace = $this->api_namespace . $this->api_version;
        $publicItems = array(
            'signup',
            'getProfile',
            'updateProfile',
            'validateToken',
            'getAllTeachers',
            'allTeachers',
            'subjectTeachers',
            'alotTimePeriod',
            'periodDetails',
            'checkAlottedPeriod',
            'checkAlottedClasses',
            'updateLoginStatus',
            'loginS',
            'getTeachersAttedance'
        );
        foreach ($publicItems as $Item) {
            register_rest_route(
                $namespace,
                '/' . $Item,
                array(
                    array(
                        'methods' => 'POST',
                        'callback' => array($this, $Item),
                        'permission_callback' => '__return_true'
                    ),
                )
            );
        }
    }

    public function init()
    {
        add_action('rest_api_init', array($this, 'register_routes'));
        add_action('rest_api_init', function () {
            remove_filter('rest_pre_serve_request', 'rest_send_cors_headers');
            add_filter('rest_pre_serve_request', function ($value) {
                header('Access-Control-Allow-Origin:*');
                header('Access-Control-Allow-Methods: POST, GET, OPTIONS, PUT, DELETE');
                header('Access-Control-Allow-Headers: Authorization, Content-Type');
                header('Access-Control-Allow-Credentials: true');
                return $value;
            });
        }, 15);
    }

    public function isUserExists($user)
    {
        global $wpdb;
        $count = $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM $wpdb->users WHERE ID = %d", $user));
        if ($count == 1) {
            return true;
        } else {
            return false;
        }
    }

    public function getUserIdByToken($token)
    {
        $decoded_array = array();
        $user_id = 0;
        if ($token) {
            try {
                $decoded = JWT::decode($token, new Key(JWT_AUTH_SECRET_KEY, apply_filters('jwt_auth_algorithm', 'HS256')));
                $decoded_array = (array) $decoded;
            } catch (\Firebase\JWT\ExpiredException $e) {
                return false;
            }
        }
        if (count($decoded_array) > 0) {
            $user_id = $decoded_array['data']->user->id;
        }
        if ($this->isUserExists($user_id)) {
            return $user_id;
        } else {
            return false;
        }
    }

    private function isValidToken()
    {
        $this->user_id  = $this->getUserIdByToken($this->user_token);
    }

    function jwt_auth($data, $user)
    {
        unset($data['user_nicename']);
        unset($data['user_display_name']);
        $result = $this->getProfile($user->ID);
        $result['token'] =  $data['token'];
        return $this->successResponse('User Logged in successfully', $result);
    }

    public function validateToken()
    {
        $this->isValidToken();
        $userId = $this->user_id ? $this->user_id : false;
        if (!$userId) {
            return $this->errorResponse('Token Expired','Error',200);
        } else {
            return $this->successResponse('Token Verified', ['user_id' => $userId]);
        }
    }

    public function signup($data)
    {
        $user_data = $data->get_json_params();
        $user_email    = sanitize_email($user_data['userEmail']);
        $user_name     = sanitize_text_field($user_data['userName']);
        $user_password = sanitize_text_field($user_data['userPassword']);
        $user_full_name = sanitize_text_field($user_data['userFullName']);
        $user_dob      = sanitize_text_field($user_data['userDOB']);
        $user_mob      = sanitize_text_field($user_data['userMob']);
        $class      = sanitize_text_field($user_data['class']);
        $subject      = sanitize_text_field($user_data['subject']);
        $userName = (explode(' ', $user_full_name));

        if (email_exists($user_email)) {
            return $this->errorResponse('Email already Registerd');
        }

        if (username_exists($user_name)) {
            return $this->errorResponse('Username already taken');
        }

        $role = 'Teacher';
        $firstName = $userName[0];
        $lastName = $userName[1];

        $userData = array(
            'user_pass' => $user_password,
            'user_login' => $user_name,
            'display_name' => $firstName,
            'first_name' => $firstName,
            'last_name' => $lastName,
            'user_email' => $user_email,
            'role' => $role
        );

        $user_id = wp_insert_user($userData);
        $user = new WP_User($user_id);
        if (!get_role('Teacher')) {
            add_role('Teacher', 'Teacher', ['read' => true]);
        }
        $user->set_role('Teacher');

        if (is_wp_error($user_id)) {
            return new WP_Error('user_creation_failed', 'Failed to create user.', ['status' => 400]);
        }
        update_user_meta($user_id, 'full_name', $user_full_name);
        update_user_meta($user_id, 'dob', $user_dob);
        update_user_meta($user_id, 'mobile_number', $user_mob);
        update_user_meta($user_id, 'class', $class);
        update_user_meta($user_id, 'subject', $subject);

        return new WP_REST_Response('User created successfully', 200);
    }


    // get user profile
    public function getProfile($user_id)
    {
        $user = get_user_by('id', $user_id);

        if (!$user) {
            return $this->errorResponse('Error user profile not found', 404);
        }
        $profileImageUrl =esc_url(wp_get_attachment_image_url(get_user_meta($user_id, 'profile_image', true), 'thumbnail'));
        $profile = array(
            'id' => $user->ID,
            'username' => $user->user_login,
            'email' => $user->user_email,
            'fullName' => !empty(get_user_meta($user_id, 'full_name', true)) ? get_user_meta($user_id, 'full_name', true) : $user->display_name,
            'firstName' => get_user_meta($user_id, 'first_name', true),
            'lastName' => get_user_meta($user_id, 'last_name', true),
            'mobileNumber' => get_user_meta($user_id, 'mobile_number', true),
            'dob' => get_user_meta($user_id, 'dob', true) ? date('Y-m-d', strtotime(get_user_meta($user_id, 'dob', true))) : get_user_meta($user_id, 'dob', true),
            'class' => get_user_meta($user_id, 'class', true),
            'subject' => get_user_meta($user_id, 'subject', true),
            'status' =>(boolean) get_user_meta($user_id, 'status', true),
            'userRole' => $user->roles[0],
            'profileImage' => $profileImageUrl ? esc_url($profileImageUrl) : site_url() . "/wp-content/uploads/2024/12/images.png"
        );

        return $profile;
    }


    // public function allTeachers($data)
    // {
    //     $this->isValidToken();
    //     $param=$data->get_json_params();
    //     $results_per_page = 5;
    //     $page=$param['page'];
    //     $offset = ($page - 1) * $results_per_page;
    //     global $wpdb;

    //     // $records = $wpdb->get_results(
    //     //     $wpdb->prepare(
    //     //     "SELECT 
    //     //     user.ID, 
    //     //     user.user_login, 
    //     //     user.user_email,
    //     //     -- m1.meta_value AS mobile_number,
    //     //     -- m2.meta_value AS profile_image,
    //     //     -- m3.meta_value AS full_name
    //     //     FROM wp_users AS user
    //     //     -- INNER JOIN wp_usermeta AS m1 
    //     //     -- ON user.ID = m1.user_id AND m1.meta_key = 'mobile_number'
    //     //     -- LEFT JOIN wp_usermeta AS m2 
    //     //     -- ON user.ID = m2.user_id AND m2.meta_key = 'profile_image'
    //     //     -- INNER JOIN wp_usermeta AS m3 
    //     //     -- ON user.ID = m3.user_id AND m3.meta_key = 'full_name'
    //     //     INNER JOIN wp_usermeta AS usermeta 
    //     //     ON user.ID = usermeta.user_id
    //     //     WHERE usermeta.meta_key = %s
    //     //     AND usermeta.meta_value LIKE %s
    //     //     LIMIT %d OFFSET %d",
    //     //     $wpdb->prefix . 'capabilities',
    //     //     '%"teacher"%',
    //     //     $results_per_page,
    //     //     $offset
    //     //     )
    //     // );
   
    //     $records=[];
    //     $total_records = $wpdb->get_var(
    //         $wpdb->prepare(
    //             "SELECT COUNT(*)
    //         FROM wp_users AS user
    //         LEFT JOIN wp_usermeta AS usermeta 
    //         ON user.ID = usermeta.user_id
    //         WHERE usermeta.meta_key = 'wp_capabilities'
    //         AND usermeta.meta_value LIKE %s",
    //             '%"teacher"%',
    //         )
    //     );
    //     $users = $wpdb->get_results(
    //         $wpdb->prepare(
    //         "SELECT *
    //         FROM wp_users AS user
    //         LEFT JOIN wp_usermeta AS usermeta 
    //         ON user.ID = usermeta.user_id
    //         WHERE usermeta.meta_key = 'wp_capabilities'
    //         AND usermeta.meta_value LIKE %s
    //         LIMIT %d OFFSET %d",
    //             '%"teacher"%',
    //             $results_per_page,
    //             $offset
    //         )
    //     );
        


    //     foreach($users as $user)
    //     {
    //         $profileImage= wp_get_attachment_image_url(get_user_meta($user->ID, 'profile_image', true), 'thumbnail') ? wp_get_attachment_image_url(get_user_meta($user->ID, 'profile_image', true), 'large') : '';
    //         $records[]=array(
    //             'id'=>$user->ID,
    //             'username'=> $user->user_login,
    //             'email'=>$user->user_email,
    //             'dob'=>get_user_meta($user->ID,'dob',true),
    //             'mob'=>get_user_meta($user->ID,'mobile_number',true),
    //             'profileImage'=> $profileImage,
    //             'fullname'=> get_user_meta($user->ID, 'full_name', true),
    //             'class' => get_user_meta($user->ID, 'class', true),
    //             'subject' => get_user_meta($user->ID, 'subject', true),

    //         );
    //     }

        
        
    //     $result['total_records'] = $total_records;
    //     $result['records'] = $records;

    //     return $this->successResponse('Success', $result);
    // }

    public function  getAllTeachers($data)
    {
        $param=$data->get_json_params();
        $this->isValidToken();
        $offset=($param['page']-1) * 4;
        $args = array(
            'role'    => 'Teacher',
            'orderby' => 'display_name',
            'order'   => 'ASC',
        );
        
        $users=get_users($args);
        $total_records=count($users);

        $args = array(
            'role'    => 'Teacher',
            'orderby' => 'display_name',
            'order'   => 'ASC',
            'number'  => 4, 
            'offset'  => $offset,   
        );

        $users = get_users($args);

        $records=[];

        foreach($users as $user)
        {
            
            $fullName=get_user_meta($user->ID,'full_name',true);
            $dob=get_user_meta($user->ID,'dob',true);
            $mobileNumber=get_user_meta($user->ID,'mobile_number',true);
            $class=get_user_meta($user->ID,'class',true);
            $subject=get_user_meta($user->ID,'subject',true);
            $status=(boolean)get_user_meta($user->ID,'status',true);
            $profileImage=wp_get_attachment_image_url(get_user_meta($user->ID,'profile_image',true),'thumbnail')? wp_get_attachment_image_url(get_user_meta($user->ID, 'profile_image', true), 'large') : '';
            $records[]=array(
                'id' => $user->ID,
                'fullname'=> $fullName,
                'username'=>$user->user_login,
                'email'=>$user->user_email,
                'dob'=>$dob,
                'roles'=>$user->roles[0],
                'mob'=> $mobileNumber,
                'profileImage'=>$profileImage,
                'class'=>$class,
                'subject'=> $subject,
                'status'=> $status?$status:false,
            );
        }
        $result['total_records']=$total_records;
        $result['records']= $records;

       return $this->successResponse('Success', $result);
    }

    public function subjectTeachers($data)
    {
        $param=$data->get_json_params();
        $args=array(
            'role'=>'Teacher'
        );
        $users=get_users($args);
        $teachers=[];
        foreach($users as $user)
        {
            if(get_user_meta($user->ID,'class',true)==$param['class'])
            {
                $teachers[]=array(
                    'id'=>$user->ID,
                    'fullName'=>get_user_meta($user->ID,'full_name',true)
                );
            }

        }

        if(empty($teachers))
        {
            return $this->errorResponse('Error No Teachers in','Error',200);
        }
        return $this->successResponse('Success', $teachers);
    }

    public function alotTimePeriod($data)
    {
        $this->isValidToken();
        $param=$data->get_json_params();
        global $wpdb;
        $tableName=$wpdb->prefix.'timeperiod';
        $data=array(
            'class'=> $param['class'],
            'subject'=> $param['subject'],
            'teacherId'=> $param['teacherId'],
            'date'=> $param['date'],
            'start_time'=> $param['startTime'],
            'end_time'=> $param['endTime'],

        );
        $inserted=$wpdb->insert($tableName,$data);
        if($inserted)
        {
            return $this->successResponse('success',  $wpdb->insert_id);
        }else
        {
            return $this->errorResponse('error');
        }
    
    }

    public function periodDetails($data)
    {
        $this->isValidToken();
        $param=$data->get_json_params();
        global $wpdb;
        $tableName=$wpdb->prefix.'timeperiod';
        $per_page_limit=3;
        $offset=($param['currentPage']-1)*$per_page_limit;
        $total_records=$wpdb->get_var("SELECT COUNT(*) FROM {$tableName}");
        $records = $wpdb->get_results("SELECT * FROM {$tableName} ORDER BY `id` DESC  LIMIT {$per_page_limit}  OFFSET {$offset}", ARRAY_A );
        if (empty($records)) {
            return $this->errorResponse('Error','Error : No Records Found');
        }
        foreach($records as &$record)
        {
            $record['teacherName'] = get_user_meta($record['teacherId'], 'full_name', true);

        }
        $result['records']=$records;
        $result['total_records']=$total_records;
        return $this->successResponse('success', $result);
    }
    public function updateProfile($request)
    {
        $this->isValidToken();
        $param = $request->get_params();
        $username = $param['username'];
        $mobileNumber = $param['mobileNumber'];
        $email = $param['email'];
        $firstName = $param['firstName'];
        $lastName = $param['lastName'];
        $fullName = $firstName . ' ' . $lastName;
        $dob = $param['dob'] ? date('Y-m-d', strtotime($param['dob'])) : $param['dob'];
        $user_id = !empty($this->user_id) ? $this->user_id : false;
        if ($user_id) {
            $upload_dir         =   wp_upload_dir();
            if ($param['profileImage']) {

                $base64_image = $param['profileImage'];
                if (preg_match('/^data:image\/(\w+);base64,/', $base64_image, $matches)) {


                    $imageType = 'image/' . $matches[1];
                    $base64data = explode(',', $base64_image)[1];
                    $decodedData = base64_decode($base64data);
                    if ($decodedData === false) {
                        return $this->errorResponse('invalid_base64', 'Base64 decoding failed.');
                    }
                    $filename           =   'profile_image';
                    $file_type          =   strtolower($matches[1]);
                    $hashed_filename    =   md5($filename . microtime()) . '.' . $file_type;
                    $file_path = $upload_dir['path'] . '/' . $hashed_filename;
                    if (file_put_contents($file_path, $decodedData) === false) {
                        return $this->errorResponse('file_save_failed', 'Failed to save the file.');
                    }
                    $attachment         =   array(
                        'post_mime_type' =>  $imageType,
                        'post_title'     =>  basename($hashed_filename),
                        'post_content'   => '',
                        'post_status'    => 'inherit',
                        'guid'           => $upload_dir['url'] . '/' . basename($hashed_filename)
                    );
                    $attach_id = wp_insert_attachment($attachment, $file_path);
                    $attach_data = wp_generate_attachment_metadata($attach_id, $file_path);
                    wp_update_attachment_metadata($attach_id, $attach_data);
                    update_user_meta($user_id, 'profile_image', $attach_id);
                } elseif (filter_var($param['profileImage'], FILTER_VALIDATE_URL)) {
                } else {
                    return $this->errorResponse('invalid_image', 'Invalid image format.');
                }
            }

            $user_data = array(
                'ID' => $user_id,
                'first_name' => $firstName,
                'last_name' => $lastName,
            );


            wp_update_user($user_data);

            update_user_meta($user_id, 'full_name', $fullName);
            update_user_meta($user_id, 'mobile_number', $mobileNumber);
            update_user_meta($user_id, 'dob', $dob);
        } else {
            return $this->errorResponse('Invalid User');
        }
        $result = $this->getProfile($user_id);
        return $this->successResponse('Profile Updated Successfully', $result);
    }

    public  function checkAlottedPeriod($data)
    {
        $this->isValidToken();
        $param=$data->get_json_params();
        $time=$param['start_time'];
        $time=explode('T',$time);
        $time=implode(' ',$time);
        $class=$param['class'];
        $date=$param['date'];
        global $wpdb;
        $tableName=$wpdb->prefix. 'timeperiod';
        $result=$wpdb->get_results("SELECT * FROM `$tableName` WHERE `class`= '$class'  AND `date`= '$date' AND `start_time`='$time'");
        if($result)
        {
            return $this->errorResponse('Error : Period Already Alloted at this time', $result,200);
        }else{
            return $this->successResponse('success',$result);
        }

    }

    public function checkAlottedClasses($data)
    {
        $param=$data->get_params();
        $teacher_id=$param['teacherId'];
        $date=$param['date'];
        if(is_wp_error($teacher_id))
        {
            return $this->errorResponse('Error','Error',200);
        }
        global $wpdb;
        $tableName=$wpdb->prefix.'timeperiod';
        $records=$wpdb->get_results("SELECT * FROM {$tableName} WHERE `teacherId`=$teacher_id AND DATE(date)='$date'");
        $total_records=$wpdb->get_var("SELECT * FROM {$tableName} WHERE `teacherId`=$teacher_id AND DATE(date)='$date'");
        $classes['total_records']= $total_records;
        $classes['records']= $records;
        return $this->successResponse('Success', $classes);
    }


   public function updateLoginStatus($data)
    {

        global $wpdb;
        $tableName=$wpdb->prefix.'teacher_attendance';
    
        $this->isValidToken();
        $user_id = $this->user_id;
        if (!$user_id) {
            return $this->errorResponse('Error User Data not Found','Error',200);
        }

        $status=$data->get_param('status');
        if($status)
        {
            update_user_meta($user_id, 'status', $status);
            date_default_timezone_set('Asia/Calcutta');
            $date = date("Y-m-d");
            $query = $wpdb->get_results($wpdb->prepare("SELECT * FROM {$tableName} WHERE `teacherId`=$user_id AND DATE(date)=' $date'"));
            if(!$query)
            {
                $loginTime = date('Y-m-d H:i:s', time());
                    $insertData = [
                        'teacherId' => $user_id,
                        'login' => $loginTime,
                        'date' => $date,
                    ];

                    $wpdb->insert($tableName, $insertData);
            }
            $timestamp = wp_next_scheduled('reset_login_status_after_timeout', [$user_id]);
            if ($timestamp) {
                wp_unschedule_event($timestamp, 'reset_login_status_after_timeout', [$user_id]);
            }
            wp_schedule_single_event(time() + HOUR_IN_SECONDS * 8, 'reset_login_status_after_timeout', [$user_id]);
            $loginStatus = "Active";
        }
        else
        {
            $timestamp = wp_next_scheduled('reset_login_status_after_timeout', [$user_id]);
            if ($timestamp) {
                wp_unschedule_event($timestamp, 'reset_login_status_after_timeout', [$user_id]);
            }
            wp_schedule_single_event(time(), 'reset_login_status_after_timeout', [$user_id]);
            $loginStatus='Inactive';

                date_default_timezone_set('Asia/Calcutta');
                $date = date("Y-m-d");
                $logoutTime = date('Y-m-d H:i:s', time());
                $logoutData=[
                    'logout'=>$logoutTime
                ];
                $where=[
                    'date'=> $date
                ];

               $wpdb->update($tableName, $logoutData,$where);
        }

        $arr['status']= $status;
        $arr['loginStatus']=$loginStatus;
        $arr['loginTime']=$loginTime;
        return  $this->successResponse('Login Status Updated Successfully : '. $loginStatus,$arr);
    }


    public function  getTeachersAttedance($data)
    {
        $param = $data->get_json_params();
        $this->isValidToken();
        $date=$param['date'];
        global $wpdb;
        $tableName=$wpdb->prefix. 'teacher_attendance';
        $offset = ($param['page'] - 1) * 4;
        $teachers=$wpdb->get_results("SELECT * FROM $tableName WHERE DATE(date)='$date'");

       
        $users= get_users(
            array(
                'role'=>'Teacher',
                'number'=>4,
                'offset'=>$offset
            )
            );

        $total_records=count(get_users(array('role'=>'Teacher')));
        foreach ($users as $user) {
            $fullName = get_user_meta($user->ID, 'full_name', true);
            $dob = get_user_meta($user->ID, 'dob', true)?date('m/d/Y',strtotime(get_user_meta($user->ID, 'dob', true))): get_user_meta($user->ID, 'dob', true);
            $mobileNumber = get_user_meta($user->ID, 'mobile_number', true);
            $class = get_user_meta($user->ID, 'class', true);
            $subject = get_user_meta($user->ID, 'subject', true);
            $status = (bool)get_user_meta($user->ID, 'status', true);
            $profileImage = wp_get_attachment_image_url(get_user_meta($user->ID, 'profile_image', true), 'thumbnail') ? wp_get_attachment_image_url(get_user_meta($user->ID, 'profile_image', true), 'large') : '';
            $login=false;
            $logout=false;
            foreach ($teachers as $teacher) {
                if ($teacher->teacherId == $user->ID) {
                    date_default_timezone_set('Asia/Calcutta');
                    $login=date('H:i A', strtotime($teacher->login)) ;
                    if($teacher->logout=='0000-00-00 00:00:00')
                    {
                        $logout = 'ACTIVE';

                    }else
                    {
                        $logout = date('h:i A', strtotime($teacher->logout));
                    }

                }
            }
            $records[] = array(
                'id' => $user->ID,
                'fullname' => $fullName,
                'email' => $user->user_email,
                'dob' => $dob,
                'roles' => $user->roles[0],
                'mob' => $mobileNumber,
                'profileImage' => $profileImage,
                'class' => $class,
                'subject' => $subject,
                'status' => $status ? $status : false,
                'loginTime' => $login,
                'logoutTime' => $logout,

            );

        
        }

        $result['total_records'] = $total_records;
        $result['records'] = $records;

        return $this->successResponse('Success', $result);
    }

    public function loginS()
    {
        global $wpdb;
        $tableName = $wpdb->prefix . 'teacher_attendance';
        $this->isValidToken();
        $user_id = $this->user_id;
        if (!$user_id) {
            return $this->errorResponse('Error User Data not Found', 'Error', 200);
        }
        $date = date("Y-m-d");
        $query = $wpdb->get_results($wpdb->prepare("SELECT * FROM {$tableName} WHERE `teacherId`=$user_id AND DATE(date)=' $date'"));
        if (!$query) {
            echo "Got Login Data";
        }else{
            echo "No Login Data";
        }
    }



}

$serverApi = new CRC_REST_API();
$serverApi->init();
add_filter('jwt_auth_token_before_dispatch', array($serverApi, 'jwt_auth'), 10, 2);
