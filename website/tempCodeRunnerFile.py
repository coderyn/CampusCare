@app.route('/admin/issues')
@login_required
@role_required('admin')
def admin_issues():
    """Admin: list and filter issues"""
    status = request.args.get('status', '')
    department = request.args.get('department', '')

    query = Issue.query
    if status:
        query = query.filter(Issue.status == status)
    if department:
        query = query.filter(Issue.department == department)

    issues = query.order_by(Issue.created_at.desc()).all()
    staff_users = User.query.filter(User.role.in_(['staff', 'maintenance', 'admin'])).all()

    departments = ['Maintenance', 'Electrical', 'Plumbing', 'Network', 'HVAC', 'Cleaning', 'Security', 'Other']

    return render_template('admin_issues.html', issues=issues, staff_users=staff_users, departments=departments, status_filter=status, department_filter=department)

@app.route('/admin/issue/<int:issue_id>')
@login_required
@role_required('admin')
def admin_view_issue(issue_id):
    """Admin: view an issue and assignment form"""
    issue = Issue.query.get_or_404(issue_id)
    staff_users = User.query.filter(User.role.in_(['staff', 'maintenance', 'admin'])).all()
    departments = ['Maintenance', 'Electrical', 'Plumbing', 'Network', 'HVAC', 'Cleaning', 'Security', 'Other']
    return render_template('admin_view_issue.html', issue=issue, staff_users=staff_users, departments=departments)

@app.route('/admin/issue/<int:issue_id>/assign', methods=['POST'])
@login_required
@role_required('admin')
def admin_assign_issue(issue_id):
    """Admin: assign issue to a user/department and update status/priority"""
    issue = Issue.query.get_or_404(issue_id)
    assigned_to = request.form.get('assigned_to')  # user id or ''
    department = request.form.get('department')
    status = request.form.get('status')
    priority = request.form.get('priority')

    if assigned_to:
        try:
            user = User.query.get(int(assigned_to))
            if user:
                issue.assigned_to = user.id
        except Exception:
            pass
    else:
        issue.assigned_to = None

    if department is not None:
        issue.department = department or None

    if status:
        issue.status = status

    if priority:
        issue.priority = priority

    db.session.commit()
    flash('Issue updated and assignment saved', 'success')
    return redirect(url_for('admin_view_issue', issue_id=issue.id))