from flask import Flask, render_template, redirect, url_for, flash, request, session
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from models.forms import EditInfluencerProfileForm, InfluencerRegistrationForm
from database import db  # Import the SQLAlchemy instance

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SECRET_KEY'] = 'your_secret_key'

db.init_app(app)  # Initialize SQLAlchemy with the app

# Import models after initializing db
from models.models import Influencer, Sponsor, User,Campaign,AdRequest

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if not user or not check_password_hash(user.password, password):
            flash('Invalid username or password', 'danger')
            return redirect(url_for('login'))

        session['user_id'] = user.id
        session['role'] = user.role
        flash('Login successful!', 'success')

        if user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif user.role == 'sponsor':
            return redirect(url_for('sponsor_dashboard'))
        elif user.role == 'influencer':
            return redirect(url_for('influencer_dashboard'))
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role')

        # Debugging print statements
        print(f"Username: {username}, Password: {password}, Role: {role}")

        # Check if the username already exists
        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))

        # Hash the password
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
        new_user = User(username=username, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()

        # Debugging print statements
        print(f"New user created with ID: {new_user.id}")

        # Handle role-specific data
        if role == 'sponsor':
            company_name = request.form.get('company_name')
            contact_person = request.form.get('contact_person')
            website = request.form.get('website')

            # Debugging print statements
            print(f"Sponsor Info: {company_name}, {contact_person}, {website}")

            new_sponsor = Sponsor(
                user_id=new_user.id,
                company_name=company_name,
                contact_person=contact_person,
                website=website
            )
            db.session.add(new_sponsor)
            db.session.commit()

        elif role == 'influencer':
            name = request.form.get('name')
            category = request.form.get('category')
            niche = request.form.get('niche')
            reach = request.form.get('reach')

            # Debugging print statements
            print(f"Influencer Info: {name}, {category}, {niche}, {reach}")

            new_influencer = Influencer(
                user_id=new_user.id,
                name=name,
                category=category,
                niche=niche,
                reach=reach
            )
            db.session.add(new_influencer)
            db.session.commit()

        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/admin_dashboard')
def admin_dashboard():
    if 'role' in session and session['role'] == 'admin':
        users = User.query.all()
        campaigns = Campaign.query.all()
        ad_requests = AdRequest.query.all()
        flagged_users = User.query.filter_by(flagged=True).all()
        flagged_campaigns = Campaign.query.filter_by(flagged=True).all()
        
        active_users_count = len(users)
        active_campaigns_count = len([campaign for campaign in campaigns if campaign.visibility == 'public'])
        ad_requests_count = len(ad_requests)
        flagged_users_count = len(flagged_users)
        flagged_campaigns_count = len(flagged_campaigns)
        
        return render_template(
            'admin_dashboard.html',
            users=users,
            campaigns=campaigns,
            ad_requests=ad_requests,
            flagged_users=flagged_users,
            flagged_campaigns=flagged_campaigns,
            active_users_count=active_users_count,
            active_campaigns_count=active_campaigns_count,
            ad_requests_count=ad_requests_count,
            flagged_users_count=flagged_users_count,
            flagged_campaigns_count=flagged_campaigns_count
        )
    else:
        return redirect(url_for('login'))

@app.route('/flag_user/<int:user_id>', methods=['POST'])
def flag_user(user_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('You need to be logged in as an admin to perform this action.', 'danger')
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    if user:
        user.flagged = True
        db.session.commit()
        flash('User flagged successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/unflag_user/<int:user_id>', methods=['POST'])
def unflag_user(user_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('You need to be logged in as an admin to perform this action.', 'danger')
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    if user:
        user.flagged = False
        db.session.commit()
        flash('User unflagged successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/flag_campaign/<int:campaign_id>', methods=['POST'])
def flag_campaign(campaign_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('You need to be logged in as an admin to perform this action.', 'danger')
        return redirect(url_for('login'))

    campaign = Campaign.query.get(campaign_id)
    if campaign:
        campaign.flagged = True
        db.session.commit()
        flash('Campaign flagged successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/unflag_campaign/<int:campaign_id>', methods=['POST'])
def unflag_campaign(campaign_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('You need to be logged in as an admin to perform this action.', 'danger')
        return redirect(url_for('login'))

    campaign = Campaign.query.get(campaign_id)
    if campaign:
        campaign.flagged = False
        db.session.commit()
        flash('Campaign unflagged successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/sponsor_dashboard')
def sponsor_dashboard():
    if 'role' in session and session['role'] == 'sponsor':
        sponsor = User.query.get(session['user_id'])  # Fetch the logged-in sponsor's details
        
        if not sponsor or not sponsor.sponsor_profile:
            flash('Sponsor profile not found', 'danger')
            return redirect(url_for('login'))

        campaigns = Campaign.query.filter_by(sponsor_id=session['user_id']).all()  # Fetch campaigns for the sponsor
        ad_requests = AdRequest.query.join(Campaign).filter(Campaign.sponsor_id == session['user_id']).all()  # Fetch ad requests for the sponsor
        
        return render_template('sponsor_dashboard.html', sponsor=sponsor, campaigns=campaigns, ad_requests=ad_requests)
    else:
        return redirect(url_for('login'))

@app.route('/create_campaign', methods=['GET', 'POST'])
def create_campaign():
    if 'user_id' not in session or session.get('role') != 'sponsor':
        flash('You need to be logged in as a sponsor to create a campaign.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        start_date = request.form['start_date']
        end_date = request.form['end_date']
        budget = request.form['budget']
        visibility = request.form['visibility']
        goals = request.form['goals']
        sponsor_id = session['user_id']

        # Convert string dates to datetime objects
        start_date = datetime.strptime(start_date, '%Y-%m-%d')
        end_date = datetime.strptime(end_date, '%Y-%m-%d')

        new_campaign = Campaign(
            name=name,
            description=description,
            start_date=start_date,
            end_date=end_date,
            budget=budget,
            visibility=visibility,
            goals=goals,
            sponsor_id=sponsor_id
        )

        db.session.add(new_campaign)
        db.session.commit()

        flash('Campaign created successfully!', 'success')
        return redirect(url_for('sponsor_dashboard'))

    return render_template('create_campaign.html')

@app.route('/edit_campaign/<int:campaign_id>', methods=['GET', 'POST'])
def edit_campaign(campaign_id):
    if 'role' in session and session['role'] == 'sponsor':
        campaign = Campaign.query.get_or_404(campaign_id)
        
        if request.method == 'POST':
            campaign.name = request.form.get('name')
            campaign.description = request.form.get('description')
            campaign.start_date = datetime.strptime(request.form.get('start_date'), '%Y-%m-%d')
            campaign.end_date = datetime.strptime(request.form.get('end_date'), '%Y-%m-%d')
            campaign.budget = float(request.form.get('budget'))
            campaign.visibility = request.form.get('visibility')
            campaign.goals = request.form.get('goals')
            
            db.session.commit()
            flash('Campaign updated successfully!', 'success')
            return redirect(url_for('sponsor_dashboard'))
        
        return render_template('edit_campaign.html', campaign=campaign)
    
    return redirect(url_for('login'))

@app.route('/delete_campaign/<int:campaign_id>')
def delete_campaign(campaign_id):
    if 'role' in session and session['role'] == 'sponsor':
        campaign = Campaign.query.get_or_404(campaign_id)
        db.session.delete(campaign)
        db.session.commit()
        flash('Campaign deleted successfully!', 'success')
        return redirect(url_for('sponsor_dashboard'))
    return redirect(url_for('login'))

@app.route('/create_ad_request', methods=['GET', 'POST'])
def create_ad_request():
    if 'role' in session and session['role'] == 'sponsor':
        if request.method == 'POST':
            campaign_id = request.form.get('campaign_id')
            influencer_username = request.form.get('influencer_name')
            messages = request.form.get('messages')
            requirements = request.form.get('requirements')
            payment_amount = float(request.form.get('payment_amount'))

            # Find influencer ID based on username
            influencer = User.query.filter_by(username=influencer_username, role='influencer').first()
            if not influencer:
                flash('Influencer not found!', 'danger')
                return redirect(url_for('create_ad_request'))

            influencer_id = influencer.id

            new_ad_request = AdRequest(campaign_id=campaign_id, influencer_id=influencer_id, 
                                       messages=messages, requirements=requirements, 
                                       payment_amount=payment_amount, status='pending')
            db.session.add(new_ad_request)
            db.session.commit()
            flash('Ad request created successfully!', 'success')
            return redirect(url_for('sponsor_dashboard'))

        campaigns = Campaign.query.all()  # Fetch all campaigns to display in the form
        influencers = User.query.filter_by(role='influencer').all()  # Fetch all influencers
        return render_template('create_ad_request.html', campaigns=campaigns, influencers=influencers)

    return redirect(url_for('login'))

@app.route('/edit_ad_request/<int:ad_request_id>', methods=['GET', 'POST'])
def edit_ad_request(ad_request_id):
    if 'role' in session and session['role'] == 'sponsor':
        ad_request = AdRequest.query.get_or_404(ad_request_id)
        
        if request.method == 'POST':
            ad_request.campaign_id = request.form.get('campaign_id')
            ad_request.influencer_id = request.form.get('influencer_id')
            ad_request.messages = request.form.get('messages')
            ad_request.requirements = request.form.get('requirements')
            ad_request.payment_amount = float(request.form.get('payment_amount'))
            ad_request.status = request.form.get('status')
            
            db.session.commit()
            flash('Ad request updated successfully!', 'success')
            return redirect(url_for('sponsor_dashboard'))
        
        campaigns = Campaign.query.all()  # Fetch all campaigns to display in the form
        return render_template('edit_ad_request.html', ad_request=ad_request, campaigns=campaigns)
    
    return redirect(url_for('login'))

@app.route('/delete_ad_request/<int:ad_request_id>')
def delete_ad_request(ad_request_id):
    if 'role' in session and session['role'] == 'sponsor':
        ad_request = AdRequest.query.get_or_404(ad_request_id)
        db.session.delete(ad_request)
        db.session.commit()
        flash('Ad request deleted successfully!', 'success')
        return redirect(url_for('sponsor_dashboard'))
    
    return redirect(url_for('login'))

@app.route('/search_influencers', methods=['GET'])
def search_influencers():
    if 'role' in session and session['role'] == 'sponsor':
        search_query = request.args.get('query', '')  # Default to empty string if no query is provided
        if search_query:  # Ensure that search_query is not empty
            influencers = User.query.filter(
                User.role == 'influencer',
                User.username.ilike(f'%{search_query}%')  # Use ilike for case-insensitive search
            ).all()
        else:
            influencers = []  # Return an empty list if no query is provided
        
        return render_template('search_influencers.html', influencers=influencers)
    
    return redirect(url_for('login'))

@app.route('/check_influencers')
def check_influencers():
    influencers = User.query.filter_by(role='influencer').all()
    return render_template('check_influencers.html', influencers=influencers)

@app.route('/edit_sponsor_profile', methods=['GET', 'POST'])
def edit_sponsor_profile():
    sponsor = Sponsor.query.filter_by(user_id=session['user_id']).first()
    
    if not sponsor:
        flash('Sponsor not found', 'danger')
        return redirect(url_for('sponsor_dashboard'))
    
    if request.method == 'POST':
        sponsor.company_name = request.form.get('company_name')
        sponsor.contact_person = request.form.get('contact_person')
        sponsor.website = request.form.get('website')
        
        db.session.commit()
        flash('Profile updated successfully', 'success')
        return redirect(url_for('sponsor_dashboard'))
    
    return render_template('edit_sponsor_profile.html', sponsor=sponsor)

# Helper Functions
def get_current_influencer():
    user_id = session.get('user_id')
    # Fetch the Influencer object using the user_id
    return Influencer.query.filter_by(user_id=user_id).first()

def search_for_campaigns(query):
    if query:
        return Campaign.query.filter(Campaign.name.like(f'%{query}%')).all()
    return Campaign.query.all()

def get_influencer_ad_requests():
    user_id = session.get('user_id')
    return AdRequest.query.filter_by(influencer_id=user_id).all()

# Route
@app.route('/influencer_dashboard')
def influencer_dashboard():
    if 'role' in session and session['role'] == 'influencer':
        influencer = get_current_influencer()
        if influencer is None:
            flash('Influencer not found.', 'error')
            return redirect(url_for('login'))
        
        query = request.args.get('query')
        campaigns = search_for_campaigns(query)
        ad_requests = get_influencer_ad_requests()
        
        return render_template('influencer_dashboard.html', 
                               influencer=influencer, 
                               campaigns=campaigns, 
                               ad_requests=ad_requests)
    
    return redirect(url_for('login'))

@app.route('/search_campaigns', methods=['GET'])
def search_campaigns():
    if 'role' in session and session['role'] == 'influencer':
        category = request.args.get('category')
        budget = request.args.get('budget')

        query = Campaign.query.filter(Campaign.visibility == 'public')
        if category:
            query = query.filter(Campaign.goals.ilike(f'%{category}%'))
        if budget:
            query = query.filter(Campaign.budget <= float(budget))

        campaigns = query.all()
        return render_template('search_campaigns.html', campaigns=campaigns)

    return redirect(url_for('login'))

# For influencers
@app.route('/influencer/view_ad_requests')
def view_ad_requests_influencer():
    if 'role' in session and session['role'] == 'influencer':
        ad_requests = AdRequest.query.filter_by(influencer_id=session['user_id']).all()
        return render_template('view_ad_requests_influencer.html', ad_requests=ad_requests)
    return redirect(url_for('login'))

# For sponsors
@app.route('/sponsor/view_ad_requests')
def view_ad_requests_sponsor():
    if 'role' in session and session['role'] == 'sponsor':
        sponsor_id = session['user_id']
        # First, get all campaign IDs associated with the sponsor
        campaign_ids = db.session.query(Campaign.id).filter_by(sponsor_id=sponsor_id).all()
        campaign_ids = [id for (id,) in campaign_ids]  # Convert list of tuples to list of ids
        
        # Then, get all ad requests associated with these campaign IDs
        ad_requests = AdRequest.query.filter(AdRequest.campaign_id.in_(campaign_ids)).all()
        return render_template('view_ad_requests_sponsor.html', ad_requests=ad_requests)
    return redirect(url_for('login'))

@app.route('/accept_ad_request/<int:ad_request_id>')
def accept_ad_request(ad_request_id):
    if 'role' in session and session['role'] == 'influencer':
        ad_request = AdRequest.query.get_or_404(ad_request_id)
        ad_request.status = 'accepted'
        db.session.commit()
        flash('Ad request accepted!', 'success')
        return redirect(url_for('view_ad_requests_influencer'))

    return redirect(url_for('login'))

@app.route('/reject_ad_request/<int:ad_request_id>')
def reject_ad_request(ad_request_id):
    if 'role' in session and session['role'] == 'influencer':
        ad_request = AdRequest.query.get_or_404(ad_request_id)
        ad_request.status = 'rejected'
        db.session.commit()
        flash('Ad request rejected!', 'success')
        return redirect(url_for('view_ad_requests_influencer'))

    return redirect(url_for('login'))

@app.route('/negotiate_ad_request/<int:ad_request_id>', methods=['GET', 'POST'])
def negotiate_ad_request(ad_request_id):
    ad_request = AdRequest.query.get_or_404(ad_request_id)
    
    if 'role' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        new_message = request.form.get('message')
        new_payment_amount = float(request.form.get('payment_amount'))
        
        # Update the ad request with new negotiation details
        ad_request.messages = new_message
        ad_request.payment_amount = new_payment_amount
        ad_request.status = 'negotiating'
        
        db.session.commit()
        flash('Ad request updated for negotiation!', 'success')
        
        # Redirect based on role
        if session['role'] == 'sponsor':
            return redirect(url_for('view_ad_requests_sponsor'))
        elif session['role'] == 'influencer':
            return redirect(url_for('view_ad_requests_influencer'))

    return render_template('negotiate_ad_request.html', ad_request=ad_request)
    
@app.route('/view_influencer_profile')
def view_influencer_profile():
    if 'role' in session and session['role'] == 'influencer':
        # Fetch the influencer from the database
        influencer = Influencer.query.filter_by(id=session['user_id']).first()

        if influencer:
            return render_template('view_influencer_profile.html', influencer=influencer)
        else:
            flash('Influencer not found.', 'error')
            return redirect(url_for('influencer_dashboard'))
    
    return redirect(url_for('login'))

@app.route('/edit_influencer_profile', methods=['GET', 'POST'])
def edit_influencer_profile():
    if 'role' in session and session['role'] == 'influencer':
        influencer = Influencer.query.filter_by(user_id=session['user_id']).first()
        if not influencer:
            flash('Influencer not found.', 'error')
            return redirect(url_for('influencer_dashboard'))

        form = EditInfluencerProfileForm(obj=influencer)

        if form.validate_on_submit():
            # Update the influencer's profile
            form.populate_obj(influencer)
            db.session.commit()
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('influencer_dashboard'))

        return render_template('edit_influencer_profile.html', form=form)
    
    return redirect(url_for('login'))

@app.route('/register_influencer', methods=['GET', 'POST'])
def register_influencer():
    form = InfluencerRegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_influencer = Influencer(
            username=form.username.data,
            password=hashed_password,
            category=form.category.data,
            niche=form.niche.data,
            reach=form.reach.data
        )
        db.session.add(new_influencer)
        db.session.commit()
        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register_influencer.html', form=form)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create tables
    app.run(debug=True)
