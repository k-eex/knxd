/*
    EIBD eib bus access and management daemon
    Copyright (C) 2005-2011 Martin Koegler <mkoegler@auto.tuwien.ac.at>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

/**
 * This 
 */

#ifndef INIFILE_H
#define INIFILE_H

#include "inih.h"
//#include <unordered_map>
#include <map>
#include <string>
#include <memory>

typedef std::pair<std::string,bool> ValueType;
typedef std::map<std::string, ValueType> ValueMap;

class IniData;
class IniSection;
typedef std::shared_ptr<IniSection> IniSectionPtr;

typedef bool (*UnseenViewer)(void *user,
    const IniSection& section, const std::string& name, const std::string& value);

class IniSection : public std::enable_shared_from_this<IniSection> {
    ValueMap values;
    IniData& parent;
    bool autogenerated; // don't write, ignore readonly

  public:
    IniSection(IniData& parent, const std::string& n, bool autogenerated = false);
    IniSection(IniData& parent, const std::string&& n, bool autogenerated = false);

    const std::string name; // aliased from the mapping's key

    const std::string& value(const std::string& name, const std::string& def);
    const std::string value(const std::string& name, const char *def);
    std::string& operator[](const char *name);
    std::string& operator[](const std::string& name) { return (*this)[name.c_str()]; }
    int value(const std::string& name, int def);
    bool value(const std::string& name, bool def);
    double value(const std::string& name, double def);

    bool add(const char *name, const char *value);

    void write(std::ostream& file);

    /** If an entry 'name=XX' exists, return section XX.
      * Otherwise if @force is set, return the empty-named section.
      * Otherwise return the current section. */
    IniSectionPtr sub(const char *name, bool force = false);
    IniSectionPtr sub(const std::string& name, bool force = false) { return this->sub(name.c_str(), force); }

    bool list_unseen(UnseenViewer uv, void *user);
};


typedef std::pair<IniSectionPtr,bool> SectionType;
typedef std::map<std::string, SectionType> SectionMap;
class IniData {
    SectionMap sections;

public:
    bool read_only = false;

    // method callback
    IniData();

    /** lookup, returns a new empty section if not found */
    IniSectionPtr& operator[](const char *name);
    IniSectionPtr& operator[](const std::string& name) { return (*this)[name.c_str()]; }

    bool add(const char *section, const char *name, const char *value);
    IniSectionPtr add_auto(std::string& section);

    int parse(const std::string& filename);
    int parse(std::istream& file);

    void write(std::ostream& file);

    bool list_unseen(UnseenViewer uv, void *user);
};

#endif
