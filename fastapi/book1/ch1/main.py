from fastapi import FastAPI, Header, Form, Response, Cookie
from bcrypt import checkpw, gensalt, hashpw
from pydantic import BaseModel
from uuid import UUID, uuid1
from enum import Enum
from pydantic import BaseModel
from typing import Optional, List, Dict
from datetime import date, datetime


app = FastAPI()

valid_users = dict()
pending_users = dict()
valid_profiles = dict()
discussion_posts = dict()
request_headers = dict()
cookies = dict()

class ValidUser(BaseModel):
    id: UUID
    username: str
    password: str
    passphrase: str


class User(BaseModel):
    username: str
    password: str

class UserType(str, Enum):
    admin = "admin"
    teacher = "teacher"
    alumni = "alumni"
    student = "student"

class UserProfile(BaseModel):
    firstname: str
    lastname: str
    middle_initial: str
    age: Optional[int] = 0
    salary: Optional[int] = 0
    birthday: date
    user_type: UserType

class PostType(str, Enum):
    information = "information" 
    inquiry = "inquiry"
    quote = "quote"
    twit = "twit"

class ForumPost(BaseModel):
    id: UUID
    topic: Optional[str] = None
    message: str
    post_type: PostType
    date_posted: datetime
    username: str

class ForumDiscussion(BaseModel):
    id: UUID
    main_post: ForumPost
    replies: Optional[List[ForumPost]] = None
    author: UserProfile

class Post(BaseModel):
    topic: Optional[str] = None
    message: str
    date_posted: datetime


@app.get("/ch1/index")
def index():
    return {"message": "Hello, World!"}


@app.get("/ch1/login")
def login(username: str, password: str):
    user = valid_users.get(username)
    if user is None:
        return {"message": "User not found"}
    if checkpw(password.encode(), user.passphrase.encode()):
        return user
    else:
        return {"message": "Invalid password"}
    
    
@app.post("/ch1/login/signup")
def signup(uname: str, passwd: str):
    if (uname == None and passwd == None):
        return {"message": "Username and password cannot be empty"}
    elif not valid_users.get(uname) == None:
        return {"message": "Username already exists"}
    else:
        user = User(username=uname, password=passwd)
        pending_users[uname] = user
        return user
    
    
@app.put("/ch1/account/profile/update/{username}/")
def update_profile(username: str, id: UUID, new_profile: UserProfile):
    user = valid_users.get(username)
    if user is None:
        return {"message": "user does not exist"}
    else:
        if user.id == id:
            valid_profiles[username] = new_profile
            return {"message": "successfully updated"}
        else:
            return {"message": "user does not exist"}



@app.patch("/ch1/account/profile/update/names/{username}")
def update_profile_names(id: UUID, username: str = '' , new_names: Optional[Dict[str, str]] = None):
    user = valid_users.get(username)
    if user == None:
        return {"message": "user does not exist"}
    elif new_names == None:
        return {"message": "new names are required"}
    else:
        if user.id == id:
            profile = valid_profiles[username]
            profile.firstname = new_names['fname']
            profile.lastname = new_names['lname']
            profile.middle_initial = new_names['mi']
            valid_profiles[username] = profile
            return {"message": "successfully updated"}
        else:
            return {"message": "user does not exist"}

        

@app.delete("/ch1/discussion/posts/remove/{username}")
def delete_discussion(username: str, id:UUID):
    user = valid_users.get(username)
    if user == None:
        return {"message": "user does not exist"}
    elif discussion_posts.get(id) == None:
        return {"message": "post does not exist"}
    else:
        del discussion_posts[id]
        
        
@app.delete("/ch1/login/remove/{username}")
def delete_user(username: str):
    if username == None:
        return {"message": "username is required"}
    del valid_users[username]
    return {"message": "user successfully deleted"}


@app.get("/ch1/login/{username}/{password}")
def login_with_token(username: str, password:str, id: UUID):
    user = valid_users.get(username)
    if user is None:
        return {"message": "User not found"}
    if user.id == id and checkpw(password.encode(), user.passphrase.encode()):
        return user
    else:
        return {"message": "Invalid credentials or ID"}
    
@app.get("/ch1/login/details/info")
def login_info():
    return {"message": "username and password are required for login"}




@app.delete("/ch1/login/remove/all")
def delete_users(usernames: List[str]):
    if not usernames:
        return {"message": "No usernames provided"}
    
    for username in usernames:
        if username in valid_users:
            del valid_users[username]
    
    return {"message": "Users successfully deleted", "deleted_users": usernames}


@app.delete("/ch1/delete/users/pending")
def delete_pending_users(accounts: List[str] = []):
    if not accounts:
        return {"message": "No accounts provided"}
    
    for account in accounts:
        if account in pending_users:
            del pending_users[account]
    
    return {"message": "Pending users successfully deleted", "deleted_accounts": accounts}


@app.get("/ch1/login/password/change")
def change_password(username: str, old_passw: str = '', new_passw: str = ''):
    passwd_len = 8
    user = valid_users.get(username)
    if user is None:
        return {"message": "User not found"}
    if not old_passw or not new_passw:
        return {"message": "Old and new passwords are required"}
    if len(new_passw) < passwd_len:
        return {"message": f"New password must be at least {passwd_len} characters long"}
    if not checkpw(old_passw.encode(), user.passphrase.encode()):
        return {"message": "Old password is incorrect"}
    new_passphrase = hashpw(new_passw.encode(), gensalt()).decode()
    user.passphrase = new_passphrase
    valid_users[username] = user
    return {"message": "Password successfully changed"}



@app.post("/ch1/login/username/unlock")
def unlock_username(id: Optional[UUID] = None):
    if id == None:
        return {"message": "token needed"}
    for key, val in valid_users.items():
        if val.id == id:
            return {"username": val.username}
    return {"message": "user does not exist"}


@app.post("/ch1/login/password/unlock")
def unlock_password(username: Optional[str] = None, id: Optional[UUID] = None):
    if username is None or id is None:
        return {"message": "username and token are required"}
    user = valid_users.get(username)
    if user is None:
        return {"message": "User not found"}
    if user.id == id:
        return {"password": user.passphrase}
    else:
        return {"message": "Invalid credentials or ID"}


@app.post("/ch1/login/validate", response_model=ValidUser)
def approve_user(user: User):
    
    if not valid_users.get(user.username) == None:
        return {"message": "User already exists"}
    else:
        valid_user = ValidUser(id=uuid1(), username= user.username, password  = user.password, passphrase = hashpw(user.password.encode(),gensalt()).decode())
        valid_users[user.username] = valid_user
        del pending_users[user.username]
        return valid_user
    
    
@app.get("/ch1/headers/verify")
def verify_headers(host: Optional[str] = Header(None), accept: Optional[str] = Header(None),
                   accept_language: Optional[str] = Header(None), accept_encoding: Optional[str] = Header(None),
                   user_agent: Optional[str] = Header(None)):
    request_headers["Host"] = host
    request_headers["Accept"] = accept
    request_headers["Accept-Language"] = accept_language
    request_headers["Accept-Encoding"] = accept_encoding
    request_headers["User-Agent"] = user_agent
    return request_headers


@app.post("/ch1/discussion/posts/add/{username}")
def post_discussion(username: str, post: Post, post_type: PostType):
    user = valid_users.get(username)
    if user is None:
        return {"message": "User not found"}
    post_id = uuid1()
    forum_post = ForumPost(id=post_id, topic=post.topic, message=post.message, 
                           post_type=post_type, date_posted=datetime.now(), username=username)
    if post_id not in discussion_posts:
        author_profile = valid_profiles.get(username)
        if author_profile is None:
            return {"message": "User profile not found"}
        discussion_posts[post_id] = ForumDiscussion(id=post_id, main_post=forum_post, author=author_profile)
    else:
        discussion_posts[post_id].replies.append(forum_post)
    return {"message": "Post added successfully", "post_id": post_id}


@app.post("/ch1/account/profile/add", response_model=UserProfile)
def add_profile(uname: str, fname: str = Form(...),
                lname: str = Form(...), mid_init: str = Form(...),
                user_age: int = Form(...), sal: float = Form(...),
                bday: str = Form(...), utype: UserType = Form(...)):
    user = valid_users.get(uname)
    if user == None:
        return UserProfile(
            firstname="", lastname="", middle_initial="",
            age=None, salary=None, birthday=date.today(),
            user_type=UserType.student
        )
    else:
        profile = UserProfile(
            firstname=fname, lastname=lname, middle_initial=mid_init,
            age=user_age, salary=int(sal), birthday=date.fromisoformat(bday),
            user_type=utype
        )
        valid_profiles[uname] = profile
        return profile
    
    
@app.post("/ch1/login/rememberme/create/")
def create_cookies(resp: Response, id: UUID, username: str = ''):
    resp.set_cookie(key="userkey", value=username)
    resp.set_cookie(key="identity", value=str(id))
    return {"message": "remember-me tokens created"}


@app.get("/ch1/login/cookies")
def access_cookie(userkey: Optional[str] = Cookie(None), 
                  identity: Optional[str] = Cookie(None)):
    cookies["userkey"] = userkey
    cookies["identity"] = identity
    return cookies