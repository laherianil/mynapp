from fastapi import FastAPI, HTTPException, status, Request, Body, Query, UploadFile
from fastapi.security import OAuth2PasswordBearer
import database
from boto3.dynamodb.conditions import Key
from datetime import datetime, timedelta
from pydantic import BaseModel
from typing import Dict, List
import json
import mytoken
import uuid, boto3, base64, os
from botocore.exceptions import NoCredentialsError, PartialCredentialsError
from dotenv import load_dotenv
import imageio

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

@app.post("/list")
def getlist(phonenumber: str, jwt: str):
        
    if jwt:
        tokenData = mytoken.verify_token(jwt)
        if tokenData['status_code'] == status.HTTP_200_OK:
            if not phonenumber:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,detail=f"{phonenumber} not records available")
            
            response = None
            table = database.db_connection()
            params = {
                'TableName': 'myn-demo',
                'KeyConditionExpression': 'pk = :pk_value',
                'ExpressionAttributeValues': {
                    ':pk_value': {'S': phonenumber}
                }
            }
            response = table.query(**params)
            
            try:
                if 'Items' in response and response['Items']:   
                    return response['Items']
                else:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='No records available')
            except Exception as e:
                raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))           
    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,detail="token missing")
    
class User(BaseModel):
    pk: str
    sk: str

@app.post("/createUser")
def registration(user: User, additional_data: Dict[str, str] = None):
    table = database.db_connection()
    item_data = {
        'pk': user.pk,
        'sk': user.sk,
        'created_at': datetime.now().isoformat()
    }  
    
    if additional_data:
        print("additional_data: ", additional_data)
        item_data.update(additional_data)

    response = table.put_item(Item=item_data)

    if not response:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,detail="some issues")
    return response

# ADD LOGIN API
@app.post("/login")
async def login(request_body: dict = Body(...,
    example={
        "pk": "string",
        "phonecode": "string",
        "countrycode": "string",
        "device_id": "string",
        "language_id": "string",
        "platform": "string",
        "platform_version": "string",
        "ip_address": "string"
    })):
    
    table = database.db_connection()
 
    phonenumber = request_body.get('pk')
    sortKey = str(datetime.now().strftime("%d%m%Y%H%M")) 
    phone_code = request_body.get('phonecode')
    country_code = request_body.get('countrycode')
    ip_address = request_body.get('ip_address')
    device_id = request_body.get('device_id')
    language_id = request_body.get('language_id')
    platform = request_body.get('platform')
    platform_version = request_body.get('platform_version')
    # created_at = request_body.get('created_at')

    if not phonenumber:
        raise HTTPException(status_code=400, detail="phone is required")

    try:
        response = None
        params = {
            'TableName': 'myn-demo',
            'KeyConditionExpression': 'pk = :pk_value',
            'ExpressionAttributeValues': {
                ':pk_value': {'S': phonenumber}
            }
        }
        response = table.query(**params)
        
        currentTime = datetime.now()
        otpExpiry = currentTime + timedelta(minutes=2)
        
        if 'Items' in response and response['Items']:
            # update record
            updateData = table.update_item(
                TableName='myn-demo',
                Key={
                    'pk': {'S': str(phonenumber)},
                    'sk': {'S': response['Items'][0]['sk']['S']}
                },
                UpdateExpression="SET otp = :otp, otp_expiration = :otp_expiration, otp_verified = :otp_verified, ip_address = :ip_address, device_id = :device_id, language_id = :language_id, platform = :platform, platform_version = :platform_version",
                ExpressionAttributeValues={
                    ':otp': {'S': '123456'},
                    ':otp_expiration': {'S': str(otpExpiry.timestamp())},
                    ':otp_verified': {'S': '0'},
                    ':ip_address': {'S': str(ip_address)},
                    ':device_id': {'S': str(device_id)},
                    ':language_id': {'S': str(language_id)},
                    ':platform': {'S': str(platform)},
                    ':platform_version': {'S': str(platform_version)}
                }
            )
            return {"message": "OTP updated successfully"}
        else:
            # create a new one
            response = table.put_item(
                TableName='myn-demo',
                Item={
                    'pk': {'S': phonenumber},
                    'sk': {'S': sortKey},
                    'myn_id': {'S': 'null'},
                    'user_id': {'S': 'null'},
                    'phone_code': {'S': phone_code},
                    'otp': {'S': '123456'},
                    'otp_expiration': {'S': str(otpExpiry.timestamp())},
                    'otp_verified': {'S': '0'},
                    'country_code': {'S': country_code},
                    'ip_address': {'S': ip_address},
                    'device_id': {'S': device_id},
                    'language_id': {'S': language_id},
                    'platform': {'S': platform},
                    'platform_version': {'S': platform_version},
                    'created_at': {'S': str(currentTime.timestamp())}
                }
            )
        return {"message": "OTP send successfully"}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ADD OTP VERIFICATION API
@app.post("/verify_otp")    
async def verifyOtp(request_body: dict = Body(...,
    example={
        "phonenumber": "string",
        "otp": "string"
    })):
    table = database.db_connection()
    userPhonenumber = request_body.get('phonenumber')
    userOTP = request_body.get('otp')
    currentTimeStamp = datetime.now().timestamp()

    if not userPhonenumber:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="phonenumber required")
    
    if not userOTP:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="otp required")
    
    try:
        params = {
            'TableName': 'myn-demo',
            'KeyConditionExpression': 'pk = :pk_value',
            'ExpressionAttributeValues': {
                ':pk_value': {'S': userPhonenumber}
            }
        }
        response = table.query(**params)

        if 'Items' in response and response['Items']:
            for item in response['Items']:
                dbPhoneNumber = item.get('pk',{}).get('S')
                dbOtp = item.get('otp',{}).get('S')
                dbOtpVerified = item.get('otp_verified',{}).get('S')
                dbOtpExpiry = item.get('otp_expiration',{}).get('S')
            
            if userOTP != dbOtp:    # check otp correct or not
                # return {"message": "Wrong OTP"}
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="wrong otp!")
            
            isOtpExpired = (currentTimeStamp - float(dbOtpExpiry)) / 60  # find difference in MINUTE
            # return isOtpExpired
            if isOtpExpired > 2:    # check otp expired or not
                # return {"message": "OTP expired"}
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="time expired, try again!")
            
            # return dbPhoneNumber+" <> "+dbOtp+" <> "+dbOtpExpiry+" <> "+dbOtpVerified
            accessToken = mytoken.create_access_token(data = {'sub':userPhonenumber})
            updateData = table.update_item(
                TableName='myn-demo',
                Key={
                    'pk': {'S': str(userPhonenumber)},
                    'sk': {'S': response['Items'][0]['sk']['S']}
                },
                UpdateExpression="SET otp_verified = :otp_verified",
                ExpressionAttributeValues={
                    ':otp_verified': {'S': '1'}
                }
            )
            return {"access_token": accessToken, "token_type": "bearer"}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,detail=str(e))

# ADD MYN_ID AND USER_ID or ONLY MYN_ID or ONLY USER_ID API
@app.post("/set_user_myn_id")    
async def setUserMynIds(request_body: dict = Body(...,
    example={
        "jwt": "string",    # jwt token
        "phonenumber": "string",    # user phonenumer
        "myn_id": "string | empty", # IF MYN_ID THERE IN THE REQUEST THEN UPDATE IT
        "user_id": "string | empty" # IF USER_ID THERE IN THE REQUET THEN UPDATE IT
    })):

    # IF MYN_ID & USER_ID BOTH ARE EMPTY IN THE REQUEST, IT MEANS FIRST TIME ADDING & IF 2ND TIME THEN DONT DO ANYTHING AS DATA ALREADY SAVED
    # IF ANY ONE ID IN THE REQUEST, IT MEANS UPDATE THE ONE ONLY AS PER REQUEST 
    jwToken = request_body.get('jwt')
    userPhonenumber = request_body.get('phonenumber')
    mynId = request_body.get('myn_id')
    userId = request_body.get('user_id')
    currentTimeStamp = datetime.now().timestamp()

    if not userPhonenumber:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="phonenumber required")
    
    try:
        if jwToken:
            tokenData = mytoken.verify_token(jwToken)
            if tokenData['status_code'] != status.HTTP_200_OK:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,detail="Invalid token")    
        else:   
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,detail="token missing")
        
        table = database.db_connection()
        # Query the table to check if the phonenumber exists
        params = {
            'TableName': 'myn-demo',
            'KeyConditionExpression': 'pk = :pk_value',
            'ExpressionAttributeValues': {
                ':pk_value': {'S': userPhonenumber}
            }
        }
        response = table.query(**params)
        
        if 'Items' in response and response['Count']:
            item = response['Items'][0]
            dbMynId = item.get('myn_id', {}).get('S')
            dbUserId = item.get('user_id', {}).get('S')
            dbSk = item.get('sk', {}).get('S')
            # Check if both IDs are empty
            if not mynId and not userId:
                if dbMynId == 'null' and dbUserId == 'null':
                    new_myn_id = generate_unique_id('myn')
                    new_user_id = generate_unique_id('user')
                    table.update_item(
                        TableName='myn-demo',
                        Key={
                            'pk': {'S': str(userPhonenumber)},
                            'sk': {'S': dbSk}
                        },
                        UpdateExpression="SET myn_id=:myn_id, user_id=:user_id",
                        ExpressionAttributeValues={
                            ':myn_id': {'S': new_myn_id},
                            ':user_id': {'S': new_user_id}
                        }
                    )
                else:
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Both IDs already exist")
            # UPDATED MYNID ONLY
            elif mynId and not userId:
                isMynIdExist = check_mynid_exist(mynId, str(userPhonenumber), dbSk, table)
                if isMynIdExist == True:
                    return {"status": False, "message": "Already used, please select new."}
                table.update_item(
                    TableName='myn-demo',
                    Key={
                        'pk': {'S': str(userPhonenumber)},
                        'sk': {'S': dbSk}
                    },
                    UpdateExpression="set myn_id=:myn_id",
                    ExpressionAttributeValues={
                        ':myn_id': {'S': mynId}
                    }
                )
            elif not mynId and userId:
                isUserIdExist = check_userid_exist(userId, str(userPhonenumber), dbSk, table)
                if isUserIdExist == True:
                    return {"status": False, "message": "Already used, please select new."}
                table.update_item(
                    TableName='myn-demo',
                    Key={
                        'pk': {'S': str(userPhonenumber)},
                        'sk': {'S': dbSk}
                    },
                    UpdateExpression="set user_id=:user_id",
                    ExpressionAttributeValues={
                        ':user_id': {'S': userId}
                    }
                )
            else:
                isMynIdExist = check_mynid_exist(mynId, str(userPhonenumber), dbSk, table)
                if isMynIdExist == True:
                    return {"status": False, "message": "MynId Already used, please select new."}
                
                isUserIdExist = check_userid_exist(userId, str(userPhonenumber), dbSk, table)
                if isUserIdExist == True:
                    return {"status": False, "message": "UserId Already used, please select new."}
                
                table.update_item(
                    TableName='myn-demo',
                    Key={
                        'pk': {'S': str(userPhonenumber)},
                        'sk': {'S': dbSk}
                    },
                    UpdateExpression="set myn_id=:myn_id, user_id=:user_id",
                    ExpressionAttributeValues={
                        ':myn_id': {'S': mynId},
                        ':user_id': {'S': userId}
                    }
                )
            return {"status": True, "message": "saved successfully"}
        else: 
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Phonenumber does not exist")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,detail=str(e))

# GENERATE UNIQUE ID USING UUID4
def generate_unique_id(prefix):
    return prefix + str(uuid.uuid4().int)[:6]

# CHECK REQUESTED MYNID EXIST IN DATABASE
def check_mynid_exist(mynId, pk, sk, table):
    params = {
        'TableName': 'myn-demo',
        'FilterExpression': 'myn_id = :myn_id',
        'ExpressionAttributeValues': {
            ':myn_id': {'S': mynId}
        }
    }
    response = table.scan(**params)
    
    if 'Items' in response and response['Count']:
        return True

# CHECK REQUESTED USERID EXIST IN DATABASE
def check_userid_exist(userId, pk, sk, table):
    params = {
        'TableName': 'myn-demo',
        'FilterExpression': 'user_id = :user_id',
        'ExpressionAttributeValues': {
            ':user_id': {'S': userId}
        }
    }
    response = table.scan(**params)
    if 'Items' in response and response['Count']:
        return True
        
# ADD POST/COMMENT API
@app.post("/add_comment")    
async def addComment(request_body: dict = Body(...,
    example={
        #"pk": "string", # comment | post OR comment | reply
        #"sk": "string", # video_id_phonenumber_timestamp
        "jwt": "string",    # jwt token
        "phonenumber": "string",    # user phonenumber
        #"parent_comment_id":"string", # REQUIRED ONLY FOR REPLY TYPE OF COMMENT
        "video_id": "string",   # video_XYZ
        "reply_to": "string | empty", # EMPTY IF COMMENT TYPE IS POST, OTHERWISE PASS SORTKEY OF PARENT POST
        "content": "string" # any text
    })):

    table = database.db_connection()
    currentTimeStamp = str(datetime.now().timestamp())

    userId = request_body.get('phonenumber')
    jwToken = request_body.get('jwt')
    videoId = request_body.get('video_id')    
    replyTo = request_body.get('reply_to')
    parentId = request_body.get('parent_comment_id')
    msg = request_body.get('content')
    
    if not userId:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="phonenumber required")
    
    try:
        if jwToken:
            tokenData = mytoken.verify_token(jwToken)
            if tokenData['status_code'] == status.HTTP_200_OK:
                pk = "comment | reply"
                SKcommentId = videoId+"_"+userId+"_"+currentTimeStamp
                if not replyTo:
                    pk = "comment | post"
                    parentId = None
                    
                response = None
                
                response = table.put_item(
                    TableName='myn-demo',
                    Item={
                        'pk': {'S': pk},
                        'sk': {'S': SKcommentId},
                        'phone': {'S': userId},
                        'video_id': {'S': videoId},
                        'reply_to': {'S': replyTo},
                        'message': {'S': msg},
                        'created_at': {'S': str(currentTimeStamp)}
                    }
                )
                return {"success": '1',"message":"comment save!"}
        else:   
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,detail="token missing")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,detail=str(e))

# LIST POST/COMMENT API
@app.post("/comment_list")    
async def commentList(request_body: dict = Body(...,
    example={
        "jwt": "string",    # jwt token
        "video_id": "string",   # video_XYZ
        "type": "string | empty", # empty = ALL COMMENTS, post = ONLY POST COMMENTS, reply = ONLY REPLYS
        "pagination_key": "string | empty",  # empty for 1st page otherwise subsequent fetch the next set of results
        "limit": 2  # number of records per page | we can pass to any number
    })):

    currentTimeStamp = str(datetime.now().timestamp())

    jwToken = request_body.get('jwt')
    videoId = request_body.get('video_id')    
    commentType = request_body.get('type')
    last_evaluated_key = request_body.get('last_evaluated_key')
    limit = request_body.get('limit', 2)
    
    if not videoId:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="video Id required")
    
    try:
        if jwToken:
            tokenData = mytoken.verify_token(jwToken)
            if tokenData['status_code'] == status.HTTP_200_OK:
                response = None
                table = database.db_connection()

                key_condition = ''
                if commentType == 'post':
                    key_condition = 'comment | post'
                elif commentType == 'reply':
                    key_condition = 'comment | reply'

                params = {
                    'TableName': 'myn-demo',
                    'KeyConditionExpression': 'pk = :pk_value AND begins_with(sk, :sk_value)',
                    'ExpressionAttributeValues': {
                        ':pk_value': {'S': key_condition},
                        ':sk_value': {'S': videoId},
                        ':video_id': {'S': videoId}
                    },
                    'FilterExpression': 'video_id = :video_id',
                    'Limit': limit,
                }

                if last_evaluated_key:
                    exclusive_start_key = {
                        'pk': {'S': key_condition},
                        'sk': {'S': last_evaluated_key}
                    }
                    params['ExclusiveStartKey'] = exclusive_start_key

                response = table.query(**params)
                # return response
                # Transform the response items to the desired format
                commentsData = [
                    {
                        'created_at': item['created_at']['S'],
                        'video_id': item['video_id']['S'],
                        'reply_to': item['reply_to']['S'],
                        'comment_id': item['sk']['S'],
                        'message': item['message']['S'],
                        'pk': item['pk']['S'],
                        'phone': item['phone']['S']
                    }
                    for item in response['Items']
                ]

                # Count replies for each post
                for comment in commentsData:
                    if comment['pk'] == 'comment | post':
                        reply_count_params = {
                            'TableName': 'myn-demo',
                            'KeyConditionExpression': 'pk = :pk_value AND begins_with(sk, :sk_value)',
                            'ExpressionAttributeValues': {
                                ':pk_value': {'S': 'comment | reply'},
                                ':sk_value': {'S': comment['video_id']},
                                ':reply_to': {'S': comment['comment_id']}
                            },
                            'FilterExpression': 'reply_to = :reply_to',
                        }
                        reply_count_response = table.query(**reply_count_params)
                        comment['reply_count'] = len(reply_count_response['Items'])
                    else:
                        comment['reply_count'] = 0

                sortedComments = sorted(commentsData, key=lambda x: x['created_at'], reverse=True)

                last_evaluated_key = response.get('LastEvaluatedKey', {})
                last_evaluated_key_str = last_evaluated_key.get('sk', {}).get('S', None)
                finalResonse = {
                    'success': False,
                    'comments': sortedComments,
                    'pagination_key': last_evaluated_key_str
                }
                if 'Items' in response and response['Items']:
                    finalResonse = {
                        'success': True,
                        'comments': sortedComments,
                        'pagination_key': last_evaluated_key_str
                    }
                return finalResonse
        else:   
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,detail="token missing")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,detail=str(e))
    
# VIDEO LIST API
@app.post("/video_list")
async def videoList(request_body: dict = Body(...,
    example={
        "jwt": "string",    # jwt token
        "video_id": "string | empty",   # video_XYZ to fetch single or video_XYZ,video_XYZ1,video_XYZ2 to fetch multiple 
        "pagination_key": "string | empty",  # empty for 1st page otherwise subsequent fetch the next set of results
        "limit": 2  # number of records per page | we can pass to any number
    })):

    currentTimeStamp = str(datetime.now().timestamp())

    jwToken = request_body.get('jwt')
    videoId = request_body.get('video_id')    
    last_evaluated_key = request_body.get('pagination_key')
    limit = request_body.get('limit', 2)
    
    if not jwToken:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="authentication failed!")
    
    try:
        if jwToken:
            tokenData = mytoken.verify_token(jwToken)
            if tokenData['status_code'] == status.HTTP_200_OK:
                response = None
                table = database.db_connection()

                if videoId:
                    video_ids = [vid.strip() for vid in videoId.split(',')]
                    if len(video_ids) == 1:
                        # Fetch single video
                        params = {
                            'TableName': 'myn-demo',
                            'KeyConditionExpression': 'pk = :pk_value AND begins_with(sk, :sk_value)',
                            'ExpressionAttributeValues': {
                                ':pk_value': {'S': 'video'},
                                ':sk_value': {'S': videoId},
                                ':video_id': {'S': videoId}
                            },
                            'FilterExpression': 'video_id = :video_id',
                            'Limit': limit,
                        }
                        # return params

                    else:
                        # Fetch multiple videos
                        filter_expressions = ['video_id = :video_id' + str(i) for i in range(len(video_ids))]
                        expression_attribute_values = {':video_id' + str(i): {'S': video_id} for i, video_id in enumerate(video_ids)}
                        expression_attribute_values[':pk_value'] = {'S': 'video'}
                        params = {
                            'TableName': 'myn-demo',
                            'KeyConditionExpression': 'pk = :pk_value',
                            'ExpressionAttributeValues': expression_attribute_values,
                            'FilterExpression': ' OR '.join(filter_expressions),
                            'Limit': limit,
                        }
                        # return params
                else:
                    # Fetch all videos
                    params = {
                        'TableName': 'myn-demo',
                        'KeyConditionExpression': 'pk = :pk_value',
                        'ExpressionAttributeValues': {
                            ':pk_value': {'S': 'video'}
                        },
                        'Limit': limit,
                    }

                if last_evaluated_key:
                    exclusive_start_key = {
                        'pk': {'S': 'video'},
                        'sk': {'S': last_evaluated_key}
                    }
                    params['ExclusiveStartKey'] = exclusive_start_key

                response = table.query(**params)
                # return response
                # Transform the response items to the desired format
                videoData = [
                    {
                        'created_at': item['created_at']['S'],
                        'video_id': item['video_id']['S'],
                        'video_url': item['video_url']['S'],
                        'video_thumb': item['video_thumb']['S'],
                        'user_id': item['user_id']['S'],
                        'product_ids': item['product_ids']['S'],
                        'is_approved': item['is_approved']['BOOL'],
                        'is_published': item['is_published']['BOOL']
                    }
                    for item in response['Items']
                ]
                last_evaluated_key = response.get('LastEvaluatedKey', {})
                last_evaluated_key_str = last_evaluated_key.get('sk', {}).get('S', None)
                finalResonse = {
                    'success': False,
                    'videos': videoData,
                    'pagination_key': last_evaluated_key_str
                }
                if 'Items' in response and response['Items']:
                    finalResonse = {
                        'success': True,
                        'videos': videoData,
                        'pagination_key': last_evaluated_key_str
                    }
                return finalResonse
        else:   
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="token missing")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

# CHECK VIDEO ID EXIST IN DATABASE
def check_videoid_exist(videoId,table):
    params = {
        'TableName': 'myn-demo',
        'FilterExpression': 'video_id = :video_id',
        'ExpressionAttributeValues': {
            ':video_id': {'S': videoId}
        }
    }
    response = table.scan(**params)
    
    if 'Items' in response and response['Count'] > 0:
        return True
    return False

# GET UNIQUE VIDEO ID
def get_unique_video_id(prefix, table):
    while True:
        newVideoId = generate_unique_id(prefix)
        if not check_videoid_exist(newVideoId, table):
            return newVideoId

# TO GENERATE THUMBNAIL FROM VIDEO
def generate_video_thumbnail(video_path, thumbnail_path):
    reader = imageio.get_reader(video_path, 'ffmpeg')
    # Extract the first frame (or any specific frame)
    image = reader.get_data(0)
    imageio.imwrite(thumbnail_path, image)

@app.post("/upload_reel")
async def uploadReel(request_body: dict = Body(...,
    example={
        "jwt": "string",    # jwt token
        "phonenumber": "string | empty",  # user phonenumber
        "video": "string | empty",   # video data from app side
        "product_ids": "string | empty",  # attached products with video 
        "short_description": "string | empty"  # video short description
    })):

    load_dotenv()

    AWS_ACCESS_KEY_ID = os.getenv('AWS_ACCESS_KEY_ID')
    AWS_SECRET_ACCESS_KEY = os.getenv('AWS_SECRET_ACCESS_KEY')
    REGION_NAME = "us-east-1" # os.getenv('REGION_NAME')
    S3_BUCKET_NAME = os.getenv('S3_BUCKET_NAME')

    # Create a session and resource for S3
    session = boto3.Session(
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        region_name=REGION_NAME
    )

    s3 = session.resource('s3')

    table = database.db_connection()
    currentTimeStamp = str(datetime.now().timestamp())

    userId = request_body.get('phonenumber')
    jwToken = request_body.get('jwt')
    videoData = request_body.get('video')    
    productIds = request_body.get('product_ids')
    shortDescription = request_body.get('short_description')
    
    if not userId:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="phonenumber required")
    
    if not videoData:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="video required")
    
    try:
        if jwToken:
            tokenData = mytoken.verify_token(jwToken)
            if tokenData['status_code'] == status.HTTP_200_OK:
                # Read the video file
                with open(videoData, 'rb') as video_file:
                    videoData = video_file.read()

                # Encode the video file to base64
                encoded_video = base64.b64encode(videoData).decode('utf-8')

                try:
                    # Decode the base64 video data
                    video_bytes = base64.b64decode(encoded_video)
                except Exception as e:
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid base64 video data")
                
                # print(f"video_filename=>{video_bytes}")
                video_filename = f"{userId}_{currentTimeStamp}.mp4"
                
                try:
                    # Upload video to S3 bucket
                    response = s3.Bucket(S3_BUCKET_NAME).put_object(Key=video_filename, Body=video_bytes, ContentType='video/mp4', ACL='public-read')
                    # Check if the upload was successful
                    if response:
                        # S3 URL for the uploaded video
                        video_url = f"https://{S3_BUCKET_NAME}.s3.{REGION_NAME}.amazonaws.com/{video_filename}"
                        newVideoId = get_unique_video_id('video_', table)

                        # Generate a thumbnail
                        thumbnail_path = f"/tmp/{newVideoId}.jpg"
                        generate_video_thumbnail(videoData, thumbnail_path)
                        # Upload the thumbnail to S3
                        with open(thumbnail_path, 'rb') as thumb_file:
                            thumbnail_bytes = thumb_file.read()

                        thumbnail_filename = f"{userId}_{currentTimeStamp}_{newVideoId}.jpg"
                        s3.Bucket(S3_BUCKET_NAME).put_object(
                            Key=thumbnail_filename,
                            Body=thumbnail_bytes,
                            ContentType='image/jpeg',
                            ACL='public-read'
                        )
                        thumbnail_url = f"https://{S3_BUCKET_NAME}.s3.{REGION_NAME}.amazonaws.com/{thumbnail_filename}"

                        # Store data in table
                        response = None
                        SKvideoId = newVideoId+'_'+userId+'_'+currentTimeStamp
                        response = table.put_item(
                            TableName='myn-demo',
                            Item={
                                'pk': {'S': 'video'},
                                'sk': {'S': SKvideoId},
                                'phone': {'S': userId},
                                'product_ids': {'S': productIds},
                                'video_id': {'S': newVideoId},
                                'video_url': {'S': video_url},
                                'video_thumb': {'S': thumbnail_url},
                                's_description': {'S': shortDescription},
                                'created_at': {'S': str(currentTimeStamp)}
                            }
                        )
                        return {
                            "success": '1',
                            "message": "Video uploaded successfully!",
                            "video_url": video_url,
                            "thumbnail_url": thumbnail_url
                        }
                    else:
                        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to upload video to S3")
                    
                except (NoCredentialsError, PartialCredentialsError) as e:
                    raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="S3 credentials error")
                except Exception as e:
                    raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
        else:   
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,detail="token missing")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,detail=str(e))