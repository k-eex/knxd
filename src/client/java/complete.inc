/*
    EIBD client library
    Copyright (C) 2005-2011 Martin Koegler <mkoegler@auto.tuwien.ac.at>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    In addition to the permissions in the GNU General Public License, 
    you may link the compiled version of this file into combinations
    with other programs, and distribute those combinations without any 
    restriction coming from the use of this file. (The General Public 
    License restrictions do apply in other respects; for example, they 
    cover modification of the file, and distribution when not linked into 
    a combine executable.)

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

  private Buffer buf;
  private Int16 ptr1;
  private Int8 ptr2;
  private Int8 ptr3;
  private Int16 ptr4;
  private EIBAddr ptr5;
  private EIBAddr ptr6;
  private Int32 ptr7;
  private int sendlen;

  private interface _complete
  {
    int complete () throws IOException;
  }

  private _complete complete = null;

  public int EIBComplete () throws IOException
  {
    if (complete == null)
      {
	errno = EINVAL;
	return -1;
      }
    return complete.complete ();
  }

