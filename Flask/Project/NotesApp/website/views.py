from flask import Blueprint, flash, jsonify,render_template, request
from flask_login import current_user,login_required
from .models import Notes
from . import db

Views = Blueprint("Views",__name__)

@Views.route('/',methods=["GET","POST"])
@login_required
def Home():
    if(request.method == "POST"):
        note = request.form.get("note")
        if not note or len(note.strip()) < 1:
            flash("Note is too short", category="error")
        else:
            new_note = Notes(data=note,user_id=current_user.id)
            db.session.add(new_note)
            db.session.commit()
            
            flash("Note Added successfully",category="success")
    return render_template("home.html",user=current_user)

@Views.route('/delete-note',methods=["POST"])
@login_required
def delete_note():
    if(request.method == "POST"):
        note_id = request.get_json().get('noteId')
        print(note_id)
        note = Notes.query.get(note_id)
        if note and note.user_id == current_user.id:
            print(note)
            db.session.delete(note)
            db.session.commit()
            return jsonify({'success': True})
    return jsonify({'success': False})
