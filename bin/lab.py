from connectAndQuery import connect_to_database, insert_to_database, delete_row_from_database
def archive_sents(postIdFromSchedule):
    scheduleDB = connect_to_database(
        "SELECT * FROM schedule;"
        )
    for row in scheduleDB:
        if row[1] == postIdFromSchedule:
            # Remove the entry from the Scheduled Posts table.
            removeRowSQL = """DELETE FROM schedule WHERE postid='%s';"""
            print("Removing scheduled post with ID '%s'." % (row[1]))
            delete_row_from_database(
                removeRowSQL, 
                (row[1],)
                )
            # Insert a new record into the Archived Posts table.
            insert_to_database(
                'INSERT INTO sent_newsletters (post_id, send_time) VALUES(%s,%s)', 
                (row[1], row[2])
                )
            print("Adding archives post with ID '%s'." % (row[1]))
            return True
    return False

if __name__ == "__main__":
    print(archive_sents(3))

