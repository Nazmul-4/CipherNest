from flask import Blueprint, jsonify, render_template, request, session
from datetime import datetime, timedelta
import sqlite3
from functools import wraps
import json
import hashlib
import re

analytics_bp = Blueprint('analytics', __name__)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

def get_db_connection():
    conn = sqlite3.connect('passwords.db')
    conn.row_factory = sqlite3.Row
    return conn

def calculate_password_strength(password):
    score = 0
    # Length check
    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1
    
    # Complexity checks
    if re.search(r"[A-Z]", password):  # Has uppercase
        score += 1
    if re.search(r"[a-z]", password):  # Has lowercase
        score += 1
    if re.search(r"\d", password):     # Has numbers
        score += 1
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):  # Has special chars
        score += 1
    
    return (score / 6) * 100  # Convert to percentage

def get_password_analytics():
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        
        # Get total password count
        total_passwords = cursor.execute('SELECT COUNT(*) FROM passwords').fetchone()[0]
        
        # Get passwords created in last 30 days
        recent_passwords = cursor.execute('''
            SELECT COUNT(*) FROM passwords 
            WHERE created_at >= date('now', '-30 days')
        ''').fetchone()[0]
        
        # Get weak passwords (strength < 50%)
        weak_passwords = cursor.execute('''
            SELECT COUNT(*) FROM passwords 
            WHERE strength < 50
        ''').fetchone()[0]
        
        # Get average password strength
        avg_strength = cursor.execute('''
            SELECT AVG(strength) FROM passwords
        ''').fetchone()[0] or 0
        
        # Get password categories distribution
        categories = cursor.execute('''
            SELECT category, COUNT(*) as count 
            FROM passwords 
            GROUP BY category
        ''').fetchall()
        
        return {
            'total_passwords': total_passwords,
            'recent_passwords': recent_passwords,
            'weak_passwords': weak_passwords,
            'avg_strength': round(avg_strength, 2),
            'categories': dict(categories) if categories else {}
        }
    
    finally:
        conn.close()

@analytics_bp.route('/analytics')
def analytics_page():
    analytics_data = get_password_analytics()
    return render_template('analytics.html', analytics=analytics_data)

@analytics_bp.route('/api/analytics')
def get_analytics():
    """API endpoint to get analytics data"""
    try:
        analytics_data = get_password_analytics()
        return jsonify({
            'success': True,
            'data': analytics_data
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@analytics_bp.route('/api/password-age')
def get_password_age():
    """Get password age distribution"""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        age_distribution = cursor.execute('''
            SELECT 
                CASE 
                    WHEN julianday('now') - julianday(created_at) <= 30 THEN '0-30 days'
                    WHEN julianday('now') - julianday(created_at) <= 90 THEN '31-90 days'
                    WHEN julianday('now') - julianday(created_at) <= 180 THEN '91-180 days'
                    ELSE 'Over 180 days'
                END as age_group,
                COUNT(*) as count
            FROM passwords
            GROUP BY age_group
        ''').fetchall()
        
        return jsonify({
            'success': True,
            'data': dict(age_distribution)
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
    finally:
        conn.close()

@analytics_bp.route('/api/security-score')
def get_security_score():
    """Calculate overall security score"""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        
        # Get various security metrics
        metrics = cursor.execute('''
            SELECT 
                AVG(strength) as avg_strength,
                COUNT(CASE WHEN strength < 50 THEN 1 END) * 100.0 / COUNT(*) as weak_password_percentage,
                COUNT(CASE WHEN julianday('now') - julianday(created_at) > 180 THEN 1 END) * 100.0 / COUNT(*) as old_password_percentage
            FROM passwords
        ''').fetchone()
        
        if metrics:
            avg_strength, weak_perc, old_perc = metrics
            
            # Calculate overall score (customize weights as needed)
            security_score = (
                (avg_strength or 0) * 0.4 +  # 40% weight to average password strength
                (100 - (weak_perc or 0)) * 0.3 +  # 30% weight to strong passwords
                (100 - (old_perc or 0)) * 0.3  # 30% weight to password freshness
            )
            
            return jsonify({
                'success': True,
                'score': round(security_score, 2),
                'metrics': {
                    'average_strength': round(avg_strength or 0, 2),
                    'weak_password_percentage': round(weak_perc or 0, 2),
                    'old_password_percentage': round(old_perc or 0, 2)
                }
            })
        
        return jsonify({
            'success': True,
            'score': 0,
            'metrics': {
                'average_strength': 0,
                'weak_password_percentage': 0,
                'old_password_percentage': 0
            }
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
    finally:
        conn.close()

@analytics_bp.route('/api/analytics/password-strength', methods=['GET'])
@login_required
def password_strength_report():
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        user_id = session['user_id']
        
        # Get password strength distribution
        strength_dist = cursor.execute('''
            SELECT 
                CASE 
                    WHEN strength >= 80 THEN 'Strong'
                    WHEN strength >= 60 THEN 'Medium'
                    ELSE 'Weak'
                END as category,
                COUNT(*) as count
            FROM passwords
            WHERE user_id = ?
            GROUP BY category
        ''', (user_id,)).fetchall()
        
        return jsonify({
            'strength_distribution': dict(strength_dist),
            'total_passwords': sum(row[1] for row in strength_dist)
        })
    finally:
        conn.close()

@analytics_bp.route('/api/analytics/reuse-analysis', methods=['GET'])
@login_required
def password_reuse_analysis():
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        user_id = session['user_id']
        
        # Find reused passwords (based on hashed values)
        reused = cursor.execute('''
            SELECT password_hash, COUNT(*) as count, GROUP_CONCAT(website) as websites
            FROM passwords
            WHERE user_id = ?
            GROUP BY password_hash
            HAVING count > 1
        ''', (user_id,)).fetchall()
        
        return jsonify({
            'reused_passwords': [
                {
                    'count': row['count'],
                    'websites': row['websites'].split(',')
                } for row in reused
            ]
        })
    finally:
        conn.close()

@analytics_bp.route('/api/analytics/update-reminders', methods=['GET'])
@login_required
def password_update_reminders():
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        user_id = session['user_id']
        
        # Find passwords older than 3 months
        old_passwords = cursor.execute('''
            SELECT website, last_updated
            FROM passwords
            WHERE user_id = ? AND
                  date(last_updated) <= date('now', '-90 days')
            ORDER BY last_updated ASC
        ''', (user_id,)).fetchall()
        
        return jsonify({
            'passwords_to_update': [dict(pwd) for pwd in old_passwords]
        })
    finally:
        conn.close()

@analytics_bp.route('/api/analytics/vulnerability-rating', methods=['GET'])
@login_required
def account_vulnerability_rating():
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        user_id = session['user_id']
        
        # Calculate overall vulnerability score
        metrics = cursor.execute('''
            SELECT 
                AVG(strength) as avg_strength,
                COUNT(CASE WHEN strength < 60 THEN 1 END) * 100.0 / COUNT(*) as weak_percentage,
                COUNT(CASE WHEN date(last_updated) <= date('now', '-90 days') THEN 1 END) * 100.0 / COUNT(*) as old_percentage,
                COUNT(DISTINCT password_hash) * 100.0 / COUNT(*) as unique_percentage
            FROM passwords
            WHERE user_id = ?
        ''', (user_id,)).fetchone()
        
        # Calculate final score (0-100)
        score = (
            (metrics['avg_strength'] or 0) * 0.4 +
            (100 - (metrics['weak_percentage'] or 0)) * 0.2 +
            (100 - (metrics['old_percentage'] or 0)) * 0.2 +
            (metrics['unique_percentage'] or 0) * 0.2
        )
        
        return jsonify({
            'vulnerability_score': round(score, 2),
            'metrics': {
                'average_strength': round(metrics['avg_strength'] or 0, 2),
                'weak_passwords_percentage': round(metrics['weak_percentage'] or 0, 2),
                'old_passwords_percentage': round(metrics['old_percentage'] or 0, 2),
                'password_uniqueness': round(metrics['unique_percentage'] or 0, 2)
            }
        })
    finally:
        conn.close()

@analytics_bp.route('/api/analytics/monthly-report', methods=['GET'])
@login_required
def monthly_security_report():
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        user_id = session['user_id']
        
        # Get monthly statistics
        month_start = datetime.now().replace(day=1).strftime('%Y-%m-%d')
        
        # New passwords created
        new_passwords = cursor.execute('''
            SELECT COUNT(*) as count
            FROM passwords
            WHERE user_id = ? AND
                  date(created_at) >= date(?)
        ''', (user_id, month_start)).fetchone()['count']
        
        # Passwords updated
        updated_passwords = cursor.execute('''
            SELECT COUNT(*) as count
            FROM passwords
            WHERE user_id = ? AND
                  date(last_updated) >= date(?) AND
                  date(last_updated) != date(created_at)
        ''', (user_id, month_start)).fetchone()['count']
        
        # Current security status
        security_status = cursor.execute('''
            SELECT 
                COUNT(*) as total,
                AVG(strength) as avg_strength,
                COUNT(CASE WHEN strength >= 80 THEN 1 END) as strong_count,
                COUNT(CASE WHEN strength < 60 THEN 1 END) as weak_count
            FROM passwords
            WHERE user_id = ?
        ''', (user_id,)).fetchone()
        
        return jsonify({
            'report_date': datetime.now().strftime('%Y-%m-%d'),
            'monthly_activity': {
                'new_passwords': new_passwords,
                'updated_passwords': updated_passwords
            },
            'security_status': {
                'total_passwords': security_status['total'],
                'average_strength': round(security_status['avg_strength'] or 0, 2),
                'strong_passwords': security_status['strong_count'],
                'weak_passwords': security_status['weak_count']
            },
            'recommendations': generate_monthly_recommendations(security_status)
        })
    finally:
        conn.close()

def generate_monthly_recommendations(security_status):
    recommendations = []
    
    if security_status['avg_strength'] < 70:
        recommendations.append("Work on improving overall password strength")
    
    if security_status['weak_passwords'] > 0:
        recommendations.append(f"Update {security_status['weak_passwords']} weak passwords")
    
    return recommendations
