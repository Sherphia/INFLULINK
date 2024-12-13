from database import db
from datetime import datetime

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    company_name = db.Column(db.String(150), nullable=True)
    industry = db.Column(db.String(100), nullable=True)
    budget = db.Column(db.Float, nullable=True)
    flagged = db.Column(db.Boolean, default=False)
    sponsor_profile = db.relationship('Sponsor', uselist=False, backref='user')
    category = db.Column(db.String(100), nullable=True)  # New field
    niche = db.Column(db.String(100), nullable=True)  # New field
    reach = db.Column(db.Float, nullable=True)  # New field for reach

    ad_requests = db.relationship('AdRequest', backref='influencer', lazy=True)

    def __repr__(self):
        return f'<User {self.username}>'

class Campaign(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    start_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    end_date = db.Column(db.DateTime, nullable=False)
    budget = db.Column(db.Float, nullable=False)
    visibility = db.Column(db.String(20), nullable=False)
    goals = db.Column(db.String(200), nullable=False)
    sponsor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    flagged = db.Column(db.Boolean, default=False)

    ad_requests = db.relationship('AdRequest', backref='campaign', lazy=True)

    def __repr__(self):
        return f'<Campaign {self.name}>'

class AdRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaign.id'), nullable=False)
    influencer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    messages = db.Column(db.Text, nullable=True)
    requirements = db.Column(db.String(200), nullable=False)
    payment_amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='pending')

    def __repr__(self):
        return f'<AdRequest {self.id}>'
    
class Sponsor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    company_name = db.Column(db.String(150), nullable=False)
    contact_person = db.Column(db.String(150), nullable=False)
    website = db.Column(db.String(150), nullable=False)

    def __repr__(self):
        return f'<Sponsor {self.name}>'

class Influencer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    niche = db.Column(db.String(100), nullable=False)
    reach = db.Column(db.String(100), nullable=False)  # You might use Integer or Float for reach

    def __repr__(self):
        return f'<Influencer {self.name}>'