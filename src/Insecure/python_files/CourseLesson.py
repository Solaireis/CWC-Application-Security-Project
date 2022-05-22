from uuid import uuid4

"""Made by Wei Ren"""
"""Edited by Clarence and Jason"""

class Lesson():
    def __init__(self, title, description, thumbnail):
        self.__title = title
        self.__description = description
        self.__thumbnail = thumbnail
        self.__lessonID = str(uuid4().hex)

    def set_title(self, title):
        self.__title = title
    def get_title(self):
        return self.__title

    def set_description(self, description):
        self.__description = description
    def get_description(self):
        return self.__description

    def set_thumbnail(self, thumbnail):
        self.__thumbnail = thumbnail
    def get_thumbnail(self):
        return self.__thumbnail
    
    def set_lessonID(self, lessonID):
        self.__lessonID = lessonID
    def get_lessonID(self):
        return self.__lessonID

# Video Data
class VideoLesson(Lesson):
    def __init__(self, title, description, thumbnail, videoPath):
        super().__init__(title, description, thumbnail)
        self.__videoPath = videoPath

    def set_videoPath(self, videoPath):
        self.__videoPath = videoPath
    def get_videoPath(self):
        return self.__videoPath

# Zoom Link --> To be changed
# Different timings for different students for different courses
class ZoomLesson(Lesson):
    def __init__(self, title, description, thumbnail, zoomURL, zoomPassword, timings, weeklyDay):
        super().__init__(title, description, thumbnail)
        self.__timings = str(timings) # a string, e.g. 13:30
        self.__zoomURL = zoomURL
        self.__zoomPassword = zoomPassword
        self.__weeklyDay = weeklyDay # a string, e.g. "Monday"

    def set_timing(self, timings):
        self.__timings = timings
    def get_timings(self):
        return self.__timings
    
    def set_weekly_day(self, weeklyDay):
        self.__weeklyDay = weeklyDay
    def get_weekly_day(self):
        return self.__weeklyDay

    def set_zoom_link(self, zoomURL):
        self.__zoomURL = zoomURL
    def get_zoom_link(self):
        return self.__zoomURL

    def set_zoom_password(self, zoomPassword):
        self.__zoomPassword = zoomPassword
    def get_zoom_password(self):
        return self.__zoomPassword