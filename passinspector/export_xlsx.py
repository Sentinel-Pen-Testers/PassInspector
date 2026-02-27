import xlsxwriter

BASE_HEADERS = [
    'DOMAIN', 'USERNAME', 'LMHASH', 'NTHASH', 'PASSWORD', 'CRACKED', 'HAS_LM',
    'BLANK_PASSWORD', 'ENABLED', 'IS_ADMIN', 'KERBEROASTABLE', 'STUDENT',
    'LOCAL_PASS_REPEAT', 'PASS_REPEAT_COUNT', 'SPRAY_USER', 'SPRAY_PASSWORD', 'NOTABLE PASSWORD', 'EMAIL',
    'JOB_TITLE', 'DESCRIPTION'
]

HIDE_COLUMNS = {'LMHASH', 'NTHASH'}
CONDITIONAL_HIDE_COLUMNS = {'ENABLED', 'IS_ADMIN', 'KERBEROASTABLE', 'STUDENT',
                            'LOCAL_PASS_REPEAT', 'SPRAY_USER', 'SPRAY_PASSWORD', 'NOTABLE PASSWORD', 'EMAIL'}


def create_formats(workbook):
    """Creates and returns cell formats for header and data cells."""
    cell_format = workbook.add_format({'align': 'top', 'font_size': 10})
    header_format = workbook.add_format({
        'align': 'top',
        'font_size': 11,
        'font_name': 'Barlow',
        'bg_color': '#D9D9D9'
    })
    return cell_format, header_format


def get_headers(user_database):
    headers = list(BASE_HEADERS)
    if any(getattr(user, "lacks_aes", False) for user in user_database):
        headers.append("LACKS_AES")
    return headers


def prepare_data(user_database, headers):
    """Prepares data for writing, tracks column widths, and determines conditional column visibility."""
    column_widths = [len(header) for header in headers]
    data = []
    false_counts = {key: 0 for key in CONDITIONAL_HIDE_COLUMNS}
    total_rows = len(user_database)

    for user in user_database:
        notable_str = ", ".join(map(str, user.notable_password)) if user.notable_password else ""
        values = [
            user.domain, user.username, user.lmhash, user.nthash,
            user.password if user.password else "",
            str(user.cracked), str(user.has_lm), str(user.blank_password),
            str(user.enabled), str(user.is_admin), str(user.kerberoastable),
            str(user.student), user.local_pass_repeat, user.pass_repeat,
            user.spray_user, user.spray_password, notable_str, user.email,
            user.job_title if user.job_title else "",
            user.description if user.description else ""
        ]
        if "LACKS_AES" in headers:
            values.append(str(getattr(user, "lacks_aes", False)))
        data.append(values)

        for col_index, value in enumerate(values):
            column_widths[col_index] = max(column_widths[col_index], len(str(value)))
            if headers[col_index] in CONDITIONAL_HIDE_COLUMNS and value == "False":
                false_counts[headers[col_index]] += 1

    return data, column_widths, false_counts, total_rows


def write_xlsx(file_date, user_database):
    """Writes user data to an Excel file with formatting and hidden columns."""
    out_filename = f"passinspector_results_{file_date}.xlsx"
    print(f"Writing results in Excel format to {out_filename}")

    with xlsxwriter.Workbook(out_filename) as workbook:
        worksheet = workbook.add_worksheet()
        cell_format, header_format = create_formats(workbook)

        worksheet.freeze_panes(1, 0)  # Freeze top row

        headers = get_headers(user_database)

        # Write headers
        for col, header in enumerate(headers):
            worksheet.write(0, col, header, header_format)

        # Prepare data
        data, column_widths, false_counts, total_rows = prepare_data(user_database, headers)

        # Write data
        for row, row_values in enumerate(data, start=1):
            for col, value in enumerate(row_values):
                worksheet.write(row, col, value, cell_format)

        # Adjust column widths
        for col, width in enumerate(column_widths):
            worksheet.set_column(col, col, width)

        # Hide specific columns
        for col, header in enumerate(headers):
            if header in HIDE_COLUMNS or (header in CONDITIONAL_HIDE_COLUMNS and false_counts[header] == total_rows):
                worksheet.set_column(col, col, None, None, {'hidden': True})

        worksheet.autofilter(0, 0, len(user_database), len(headers) - 1)  # Enable filtering
